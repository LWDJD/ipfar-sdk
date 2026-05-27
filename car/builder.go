// Package car provides CAR v2 file generation for IPFAR.
// Uses the standard go-car/v2 library to produce spec-compliant CAR v2 files.
package car

import (
	"bytes"
	"context"
	"fmt"

	carv2 "github.com/ipld/go-car/v2"
	"github.com/ipld/go-car/v2/index"
	"github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
	"github.com/multiformats/go-varint"
)

// BuildCAR creates a standard CAR v2 file from the given data and root CID.
// The data is wrapped in a single raw block and the provided rootCID is set
// as the CAR root. Returns the complete CAR bytes ready for Arweave upload.
//
// Uses the standard CBOR pragma + 40-byte header format as per the CAR v2 spec.
func BuildCAR(ctx context.Context, data []byte, rootCID string) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	root, err := cid.Decode(rootCID)
	if err != nil {
		return nil, fmt.Errorf("invalid root CID %q: %w", rootCID, err)
	}

	// Compute the data block CID (raw codec, sha2-256).
	dataCID, err := createRawCID(data)
	if err != nil {
		return nil, fmt.Errorf("failed to create data CID: %w", err)
	}

	// Build CAR v1 data in a buffer (standard CBOR header + varint blocks).
	var v1Buf bytes.Buffer

	// Write standard CBOR-encoded CAR v1 header.
	// Format: ld-varint(cbor_len) + CBOR(map{"Roots": [CID], "Version": 1})
	v1Header := buildCBORV1Header([]cid.Cid{root})
	v1Buf.Write(v1Header)

	// Write the data block.
	blockBytes := encodeBlock(dataCID, data)
	v1Buf.Write(blockBytes)

	// Wrap as CAR v2 using go-car/v2's WrapV1.
	// This generates a proper index and the standard CAR v2 wrapper.
	var v2Buf bytes.Buffer
	if err := carv2.WrapV1(bytes.NewReader(v1Buf.Bytes()), &v2Buf); err != nil {
		return nil, fmt.Errorf("failed to wrap CAR v1 as CAR v2: %w", err)
	}

	return v2Buf.Bytes(), nil
}

// createRawCID creates a CID v1 with raw codec (0x55) and sha2-256 multihash.
func createRawCID(data []byte) (cid.Cid, error) {
	hash, err := mh.Sum(data, mh.SHA2_256, -1)
	if err != nil {
		return cid.Undef, err
	}
	return cid.NewCidV1(cid.Raw, hash), nil
}

// buildCBORV1Header builds the standard CAR v1 header in CBOR format.
// The CBOR encoding is: ld-varint(cbor_len) + CBOR(map{"Roots": [...], "Version": 1})
func buildCBORV1Header(roots []cid.Cid) []byte {
	// Build the CBOR data:
	// a2                          — map(2)
	//   65 72 6f 6f 74 73         — text(5) "roots"
	//   8x                         — array(len(roots))
	//     for each CID:
	//       d8 2a                  — tag(42)
	//         58 <len>             — bytes(<len>)
	//           <cid bytes>
	//   67 76 65 72 73 69 6f 6e   — text(7) "version"
	//   01                         — uint(1)
	var cborBuf bytes.Buffer

	// map(2)
	cborBuf.WriteByte(0xa2)

	// key "roots"
	cborBuf.WriteByte(0x65)
	cborBuf.WriteString("roots")

	// array of roots
	encodeCBORArray(&cborBuf, len(roots))
	for _, r := range roots {
		// CID binary: prefix with multibase identity byte (0x00) for CBOR encoding
		rawBytes := r.Bytes()
		cidBytes := make([]byte, 1+len(rawBytes))
		cidBytes[0] = 0x00 // multibase identity prefix
		copy(cidBytes[1:], rawBytes)
		// tag(42)
		cborBuf.WriteByte(0xd8)
		cborBuf.WriteByte(0x2a)
		// bytes(cidLen)
		encodeCBORBytes(&cborBuf, cidBytes)
	}

	// key "version"
	cborBuf.WriteByte(0x67)
	cborBuf.WriteString("version")

	// value 1
	cborBuf.WriteByte(0x01)

	cborData := cborBuf.Bytes()

	// Wrap with ld-format: varint(cbor_len) + cbor_data
	var buf bytes.Buffer
	buf.Write(varint.ToUvarint(uint64(len(cborData))))
	buf.Write(cborData)

	return buf.Bytes()
}

// encodeCBORArray writes a CBOR array header for the given length.
func encodeCBORArray(buf *bytes.Buffer, length int) {
	n := uint64(length)
	switch {
	case n <= 23:
		buf.WriteByte(0x80 | byte(n))
	case n <= 0xff:
		buf.WriteByte(0x98)
		buf.WriteByte(byte(n))
	case n <= 0xffff:
		buf.WriteByte(0x99)
		buf.WriteByte(byte(n >> 8))
		buf.WriteByte(byte(n))
	default:
		buf.WriteByte(0x9a)
		buf.WriteByte(byte(n >> 24))
		buf.WriteByte(byte(n >> 16))
		buf.WriteByte(byte(n >> 8))
		buf.WriteByte(byte(n))
	}
}

// encodeCBORBytes writes a CBOR byte string (major type 2).
func encodeCBORBytes(buf *bytes.Buffer, data []byte) {
	n := len(data)
	switch {
	case n <= 23:
		buf.WriteByte(0x40 | byte(n))
	case n <= 0xff:
		buf.WriteByte(0x58)
		buf.WriteByte(byte(n))
	case n <= 0xffff:
		buf.WriteByte(0x59)
		buf.WriteByte(byte(n >> 8))
		buf.WriteByte(byte(n))
	default:
		buf.WriteByte(0x5a)
		buf.WriteByte(byte(n >> 24))
		buf.WriteByte(byte(n >> 16))
		buf.WriteByte(byte(n >> 8))
		buf.WriteByte(byte(n))
	}
	buf.Write(data)
}

// encodeBlock encodes a single block: varint(cidLen+dataLen) + CID bytes + data
func encodeBlock(c cid.Cid, data []byte) []byte {
	var buf bytes.Buffer
	sectionLen := uint64(c.ByteLen() + len(data))
	buf.Write(varint.ToUvarint(sectionLen))
	buf.Write(c.Bytes())
	buf.Write(data)
	return buf.Bytes()
}

// Ensure we use the imported packages.
var _ = index.WriteTo
