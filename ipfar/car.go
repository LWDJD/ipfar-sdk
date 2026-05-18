package ipfar

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
	"github.com/multiformats/go-varint"
)

// ── CAR v2 pragma (standard CBOR format) ───────────────────────────────

var carv2Pragma = []byte{
	0x0a,                                     // uint(10) — outer CBOR map length
	0xa1,                                     // map(1)
	0x67,                                     // string(7)
	0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, // "version"
	0x02,                                     // uint(2)
}

// ── CAR v2 builder ─────────────────────────────────────────────────────

// BuildCarV2 creates a CAR v2 file with a single raw block containing data.
// Returns the CAR bytes, the root CID, and an error if any.
func BuildCarV2(data []byte) (carBytes []byte, rootCID cid.Cid, err error) {
	// Create raw CID for the data block
	hash, err := mh.Sum(data, mh.SHA2_256, -1)
	if err != nil {
		return nil, cid.Undef, fmt.Errorf("failed to hash data: %w", err)
	}
	rootCID = cid.NewCidV1(cid.Raw, hash)

	// Build CAR v1 header
	v1Header := buildV1Header([]cid.Cid{rootCID})

	// Build data block: varint(sectionLen) + CID bytes + data
	sectionLen := uint64(rootCID.ByteLen() + len(data))
	dataBlock := new(bytes.Buffer)
	dataBlock.Write(varint.ToUvarint(sectionLen))
	dataBlock.Write(rootCID.Bytes())
	dataBlock.Write(data)

	// Build index
	indexEntries := buildIndex(rootCID, uint64(len(v1Header)))
	// Pad index to 8-byte alignment
	padLen := (8 - (len(indexEntries) % 8)) % 8
	if padLen > 0 {
		indexEntries = append(indexEntries, make([]byte, padLen)...)
	}

	// Compute offsets
	pragmaSize := len(carv2Pragma)
	v2HeaderSize := 40
	dataOffset := pragmaSize + v2HeaderSize
	dataSize := len(v1Header) + dataBlock.Len()
	indexOffset := dataOffset + dataSize

	// Build CAR v2 header
	v2Header := buildV2Header(uint64(dataOffset), uint64(dataSize), uint64(indexOffset))

	// Assemble
	var buf bytes.Buffer
	buf.Write(carv2Pragma)
	buf.Write(v2Header)
	buf.Write(v1Header)
	buf.Write(dataBlock.Bytes())
	buf.Write(indexEntries)

	return buf.Bytes(), rootCID, nil
}

// buildV1Header builds a legacy-format CAR v1 header.
// Format: varint(1) + varint(rootCount) + for each: varint(cidLen) + cidBytes
func buildV1Header(roots []cid.Cid) []byte {
	var buf bytes.Buffer
	buf.Write(varint.ToUvarint(1))                 // version
	buf.Write(varint.ToUvarint(uint64(len(roots)))) // root count
	for _, r := range roots {
		rb := r.Bytes()
		buf.Write(varint.ToUvarint(uint64(len(rb))))
		buf.Write(rb)
	}
	return buf.Bytes()
}

// buildV2Header builds a standard 40-byte CAR v2 header.
func buildV2Header(dataOffset, dataSize, indexOffset uint64) []byte {
	hdr := make([]byte, 40)
	binary.LittleEndian.PutUint64(hdr[16:24], dataOffset)
	binary.LittleEndian.PutUint64(hdr[24:32], dataSize)
	binary.LittleEndian.PutUint64(hdr[32:40], indexOffset)
	return hdr
}

// buildIndex builds the CAR v2 index section for a single block.
// Format: varint(entryLen) + varint(cidLen) + CID bytes + varint(offset)
func buildIndex(c cid.Cid, offset uint64) []byte {
	cidBytes := c.Bytes()
	entryContent := new(bytes.Buffer)
	entryContent.Write(varint.ToUvarint(uint64(len(cidBytes))))
	entryContent.Write(cidBytes)
	entryContent.Write(varint.ToUvarint(offset))

	var buf bytes.Buffer
	buf.Write(varint.ToUvarint(uint64(entryContent.Len())))
	buf.Write(entryContent.Bytes())
	return buf.Bytes()
}

// ComputeCID computes the CID v1 with raw codec and sha2-256 for the given data.
func ComputeCID(data []byte) (cid.Cid, error) {
	hash, err := mh.Sum(data, mh.SHA2_256, -1)
	if err != nil {
		return cid.Undef, fmt.Errorf("failed to hash data: %w", err)
	}
	return cid.NewCidV1(cid.Raw, hash), nil
}
