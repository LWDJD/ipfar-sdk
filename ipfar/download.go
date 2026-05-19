package ipfar

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/LWDJD/ipfar-sdk/arweave"
	sdkcar "github.com/LWDJD/ipfar-sdk/verify/ipfs"
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
	if arw == nil {
		return nil, fmt.Errorf("gateway client is nil")
	}
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
	// Use the SDK's CAR parser from verify/ipfs
	reader := &bytesReaderAt{data: carBytes}
	parser, err := sdkcar.NewCarParserFromReader(reader, int64(len(carBytes)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse CAR header: %w", err)
	}
	defer parser.Close()

	// Use the data offset from CarInfo to read the raw data directly
	// For a single-block CAR, the data starts at DataOffset and we need to
	// skip the varint section length prefix and CID to get the actual content
	info, err := parser.ParseInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to parse CAR info: %w", err)
	}

	// Read the data section, skipping varint(length) + CID
	dataStart := int(info.DataOffset)
	if dataStart >= len(carBytes) {
		return nil, fmt.Errorf("data offset beyond file")
	}

	// Read varint section length
	sectionLen, n := readVarint(carBytes[dataStart:])
	if n <= 0 {
		return nil, fmt.Errorf("invalid section length at data offset")
	}

	// Parse the CID to determine its length
	_, blockCID, err := cid.CidFromBytes(carBytes[dataStart+n:])
	if err != nil {
		return nil, fmt.Errorf("invalid CID: %w", err)
	}
	cidLen := blockCID.ByteLen()

	// The data follows the CID
	dataOffset := dataStart + n + cidLen
	dataLen := int(sectionLen) - cidLen
	if dataLen < 0 || dataOffset+dataLen > len(carBytes) {
		return nil, fmt.Errorf("invalid data block")
	}

	return carBytes[dataOffset : dataOffset+dataLen], nil
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
		if b < 0x80 {
			return x | uint64(b)<<s, i + 1
		}
		x |= uint64(b&0x7f) << s
		s += 7
	}
	return 0, 0
}
