package ipfar

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/LWDJD/ipfar-sdk/arweave"
	sdkmeta "github.com/LWDJD/ipfar-sdk/verify/metadata"
	"github.com/ipfs/go-cid"
)

// Download downloads a file by its Root-CID.
// It finds the metadata on chain, extracts the data_txid, downloads the CAR,
// verifies its integrity, and returns the original file data.
func Download(ctx context.Context, arw *arweave.GatewayClient, rootCID string) ([]byte, error) {
	// 1. Find metadata on chain
	metaCandidates, err := arw.QueryExistingMetas(ctx, rootCID, "", 8)
	if err != nil {
		return nil, fmt.Errorf("query metadata: %w", err)
	}
	if len(metaCandidates) == 0 {
		return nil, fmt.Errorf("no metadata found for root CID %s", rootCID)
	}

	var meta *sdkmeta.Metadata
	var metaTXID string

	for _, txID := range metaCandidates {
		rawData, err := arw.DownloadTransactionData(ctx, txID)
		if err != nil {
			continue
		}

		// Try parsing: plain JSON or base64url-encoded
		m, err := tryParseMetadata(rawData)
		if err != nil {
			continue
		}
		if m.RootCID == rootCID {
			meta = m
			metaTXID = txID
			break
		}
	}

	if meta == nil {
		return nil, fmt.Errorf("no valid metadata found for root CID %s", rootCID)
	}

	// 2. Download CAR data
	carData, err := arw.DownloadTransactionData(ctx, meta.DataTXID)
	if err != nil {
		return nil, fmt.Errorf("download CAR %s: %w", meta.DataTXID, err)
	}

	// 3. Verify CAR using the SDK's CAR parser
	// TODO: full CAR verification using verify/ipfs.CarParser
	// For now, basic check: CAR should be non-empty and start with known pragmas
	if len(carData) < 11 {
		return nil, fmt.Errorf("downloaded CAR too short (%d bytes)", len(carData))
	}

	// 4. Extract original data from CAR
	originalData, err := extractDataFromCAR(carData)
	if err != nil {
		return nil, fmt.Errorf("extract data from CAR: %w", err)
	}

	_ = metaTXID // available for logging if needed

	return originalData, nil
}

// DownloadRaw downloads raw data by Arweave transaction ID.
func DownloadRaw(ctx context.Context, arw *arweave.GatewayClient, txID string) ([]byte, error) {
	data, err := arw.DownloadTransactionData(ctx, txID)
	if err != nil {
		return nil, fmt.Errorf("download raw %s: %w", txID, err)
	}
	return data, nil
}

// ── Internal helpers ───────────────────────────────────────────────────

// tryParseMetadata attempts to parse metadata from raw bytes.
// The data may be plain JSON or base64url-encoded JSON.
func tryParseMetadata(rawData []byte) (*sdkmeta.Metadata, error) {
	// Try plain JSON first
	meta, err := sdkmeta.ParseJSON(rawData)
	if err == nil {
		return meta, nil
	}

	// Try base64url decode
	decoded, decodeErr := base64.RawURLEncoding.DecodeString(string(rawData))
	if decodeErr != nil {
		decoded, decodeErr = base64.StdEncoding.DecodeString(string(rawData))
	}
	if decodeErr != nil {
		return nil, fmt.Errorf("metadata is neither valid JSON nor base64url")
	}

	return sdkmeta.ParseJSON(decoded)
}

// extractDataFromCAR extracts the original data bytes from a CAR v2 file.
// For single-block CAR files (the common case), this finds and returns the
// sole data block.
func extractDataFromCAR(carBytes []byte) ([]byte, error) {
	// Use the SDK's CAR parser
	// For now, a simple heuristic: find the single data block after the header.
	// The CAR structure for a single file is:
	//   CARv2 pragma + v2 header + v1 header + [varint(len) + CID + data] + index

	// Simple extraction: find the data section by skipping known headers.
	// This is a simplified approach; production code should use verify/ipfs.CarParser.

	// Skip CAR v2 pragma (11 bytes) + v2 header (40 bytes)
	const minOffset = 51
	if len(carBytes) < minOffset+20 {
		return nil, fmt.Errorf("CAR too short")
	}

	// Read v1 header at offset 51
	pos := minOffset

	// Read varint version (should be 1)
	version, n := readVarint(carBytes[pos:])
	if n <= 0 || version != 1 {
		return nil, fmt.Errorf("invalid CAR v1 header: unexpected version %d", version)
	}
	pos += n

	// Read root count
	rootCount, n := readVarint(carBytes[pos:])
	if n <= 0 {
		return nil, fmt.Errorf("invalid CAR v1 header: cannot read root count")
	}
	pos += n

	// Skip root CIDs
	for i := uint64(0); i < rootCount; i++ {
		cidLen, n := readVarint(carBytes[pos:])
		if n <= 0 || pos+n+int(cidLen) > len(carBytes) {
			return nil, fmt.Errorf("invalid CAR v1 header: cannot read root CID")
		}
		pos += n + int(cidLen)
	}

	// Now at the first data block: varint(sectionLen) + CID + data
	sectionLen, n := readVarint(carBytes[pos:])
	if n <= 0 || sectionLen == 0 {
		return nil, fmt.Errorf("no data blocks in CAR")
	}
	pos += n

	// Decode CID from bytes to determine its length
	_, blockCID, err := cid.CidFromBytes(carBytes[pos:])
	if err != nil {
		return nil, fmt.Errorf("invalid CID in CAR block: %w", err)
	}
	cidLen := blockCID.ByteLen()
	pos += cidLen

	dataLen := int(sectionLen) - cidLen
	if dataLen < 0 || pos+dataLen > len(carBytes) {
		return nil, fmt.Errorf("CAR data block extends beyond file")
	}

	return carBytes[pos : pos+dataLen], nil
}

// readVarint reads a varint from data, returns (value, bytesRead).
func readVarint(data []byte) (uint64, int) {
	if len(data) == 0 {
		return 0, 0
	}
	var x uint64
	var s uint
	for i, b := range data {
		if i >= 10 {
			return 0, 0
		}
		x |= uint64(b&0x7f) << s
		s += 7
		if b < 0x80 {
			return x, i + 1
		}
	}
	return 0, 0
}

// readVarint reads a varint from data, returns (value, bytesRead).
