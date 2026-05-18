// Package car provides CAR v2 file generation for IPFAR.
// Converts raw data into CAR v2 format with CBOR index, ready for Arweave upload.
package car

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"

	"github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
	"github.com/multiformats/go-varint"
)

// carv2Pragma is the standard CBOR-encoded CAR v2 pragma: {"version": 2}
// Spec: https://ipld.io/specs/transport/car/carv2/
var carv2Pragma = []byte{
	0x0a,                                     // uint(10) — outer CBOR map length
	0xa1,                                     // map(1)
	0x67,                                     // string(7)
	0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, // "version"
	0x02,                                     // uint(2)
}

// BuildCAR creates a CAR v2 file from the given data and root CID.
// The data is wrapped in a raw block and the provided rootCID is set
// as the CAR root. Returns the complete CAR bytes ready for Arweave upload.
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

	// Build v1 header: version=1, roots=[root]
	v1Header := buildV1Header([]cid.Cid{root})

	// Encode the single data block.
	blockBytes := encodeBlock(dataCID, data)

	// Build the CBOR index.
	index := buildIndex([]indexEntry{
		{cid: dataCID, offset: 0},
	})

	// Pad index to 8-byte alignment (standard practice).
	padLen := (8 - (len(index) % 8)) % 8
	if padLen > 0 {
		index = append(index, make([]byte, padLen)...)
	}

	// Compute offsets.
	pragmaSize := int64(len(carv2Pragma))
	v2HeaderSize := int64(40)
	v1HeaderSize := int64(len(v1Header))
	dataOffset := pragmaSize + v2HeaderSize
	dataSize := v1HeaderSize + int64(len(blockBytes))
	indexOffset := dataOffset + dataSize

	v2Header := buildV2Header(uint64(dataOffset), uint64(dataSize), uint64(indexOffset))

	// Assemble.
	var buf bytes.Buffer

	// CAR v2 pragma
	buf.Write(carv2Pragma)

	// V2 header (40 bytes)
	buf.Write(v2Header)

	// V1 header + data blocks
	buf.Write(v1Header)
	buf.Write(blockBytes)

	// Index
	buf.Write(index)

	return buf.Bytes(), nil
}

// createRawCID creates a CID v1 with raw codec (0x55) and sha2-256 multihash.
func createRawCID(data []byte) (cid.Cid, error) {
	hash, err := mh.Sum(data, mh.SHA2_256, -1)
	if err != nil {
		return cid.Undef, err
	}
	return cid.NewCidV1(cid.Raw, hash), nil
}

// buildV1Header builds the CAR v1 header bytes.
// Format: varint(version=1) + varint(rootCount) + for each: varint(cidLen) + cidBytes
func buildV1Header(roots []cid.Cid) []byte {
	var buf bytes.Buffer

	// Version = 1
	buf.Write(varint.ToUvarint(1))

	// Root count
	buf.Write(varint.ToUvarint(uint64(len(roots))))

	for _, root := range roots {
		rootBytes := root.Bytes()
		buf.Write(varint.ToUvarint(uint64(len(rootBytes))))
		buf.Write(rootBytes)
	}

	return buf.Bytes()
}

// buildV2Header builds the standard CAR v2 header (40 bytes):
//
//	Characteristics [16]byte  — all zeros
//	DataOffset      uint64 LE
//	DataSize        uint64 LE
//	IndexOffset     uint64 LE
func buildV2Header(dataOffset, dataSize, indexOffset uint64) []byte {
	hdr := make([]byte, 40)
	binary.LittleEndian.PutUint64(hdr[16:24], dataOffset)
	binary.LittleEndian.PutUint64(hdr[24:32], dataSize)
	binary.LittleEndian.PutUint64(hdr[32:40], indexOffset)
	return hdr
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

// indexEntry is a single CID → offset mapping for the CAR v2 index.
type indexEntry struct {
	cid    cid.Cid
	offset uint64
}

// buildIndex builds the CBOR-encoded CAR v2 index.
// Format: CBOR array of [CID, offset] pairs.
// Each entry is encoded as a CBOR array of length 2:
//
//	[tag(42) bytes(CID), uint(offset)]
func buildIndex(entries []indexEntry) []byte {
	// We build the index in the "indexSorted" format used by go-car/v2:
	// It's a CBOR array where each element is [CID bytes, offset].
	var buf bytes.Buffer

	for _, entry := range entries {
		cidBytes := entry.cid.Bytes()

		// Build a single index entry: [tag(42) bytes(CID), uint(offset)]
		// CBOR array(2)
		entryBuf := encodeCBORArray2(cidBytes, entry.offset)

		// Prepend varint length of this entry
		buf.Write(varint.ToUvarint(uint64(len(entryBuf))))
		buf.Write(entryBuf)
	}

	return buf.Bytes()
}

// encodeCBORArray2 encodes [tag(42) bytes(CID), uint(offset)] as CBOR.
//
//	0x82                — array(2)
//	  0xd8 0x2a         — tag(42) (CID tag)
//	    0x58 <len>      — bytes(<len>)
//	      <cid bytes>
//	  <offset encoded as uint>
func encodeCBORArray2(cidBytes []byte, offset uint64) []byte {
	var buf bytes.Buffer

	// array(2)
	buf.WriteByte(0x82)

	// tag(42) bytes(CID)
	buf.WriteByte(0xd8) // tag (major 6)
	buf.WriteByte(0x2a) // tag number 42 (CID)

	// bytes(cidLen)
	encodeCBORBytes(&buf, cidBytes)

	// uint(offset)
	encodeCBORUint(&buf, offset)

	return buf.Bytes()
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

// encodeCBORUint writes a CBOR unsigned integer (major type 0).
func encodeCBORUint(buf *bytes.Buffer, v uint64) {
	switch {
	case v <= 23:
		buf.WriteByte(byte(v))
	case v <= 0xff:
		buf.WriteByte(0x18)
		buf.WriteByte(byte(v))
	case v <= 0xffff:
		buf.WriteByte(0x19)
		buf.WriteByte(byte(v >> 8))
		buf.WriteByte(byte(v))
	case v <= 0xffffffff:
		buf.WriteByte(0x1a)
		buf.WriteByte(byte(v >> 24))
		buf.WriteByte(byte(v >> 16))
		buf.WriteByte(byte(v >> 8))
		buf.WriteByte(byte(v))
	default:
		buf.WriteByte(0x1b)
		buf.WriteByte(byte(v >> 56))
		buf.WriteByte(byte(v >> 48))
		buf.WriteByte(byte(v >> 40))
		buf.WriteByte(byte(v >> 32))
		buf.WriteByte(byte(v >> 24))
		buf.WriteByte(byte(v >> 16))
		buf.WriteByte(byte(v >> 8))
		buf.WriteByte(byte(v))
	}
}
