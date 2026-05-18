package ipfar

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/LWDJD/ipfar-sdk/arweave"
	sdkmeta "github.com/LWDJD/ipfar-sdk/verify/metadata"
)

// UploadOptions holds optional configuration for the Upload function.
type UploadOptions struct {
	PoWWorkers  int      // Number of parallel PoW workers (0 = default)
	Bundle      bool     // Whether to use ANS-104 bundle upload
	GatewayURLs []string // Fallback gateways for dedup verification
}

// Upload uploads a file to Arweave with IPFAR metadata.
//
// Steps:
//  1. Compute CID of the file
//  2. Build CAR v2
//  3. Dedup: check if CAR already exists on chain
//  4. Upload CAR (if not dedup'd) via chunked upload
//  5. Build metadata JSON (raw, not base64-wrapped)
//  6. Dedup: check if metadata already exists
//  7. Upload metadata (raw JSON)
//
// Returns UploadResult with txids.
func Upload(ctx context.Context, arw *arweave.GatewayClient, wallet *arweave.Wallet, filePath string, opts *UploadOptions) (*UploadResult, error) {
	if opts == nil {
		opts = &UploadOptions{}
	}

	result := &UploadResult{}

	// ── 1. Read file and compute CID ──────────────────────────────────
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return result, fmt.Errorf("read file: %w", err)
	}
	result.DataSize = int64(len(fileData))

	rootCID, err := ComputeCID(fileData)
	if err != nil {
		return result, fmt.Errorf("compute CID: %w", err)
	}
	result.RootCID = rootCID.String()

	// ── 2. Build CAR v2 ──────────────────────────────────────────────
	carBytes, _, err := BuildCarV2(fileData)
	if err != nil {
		return result, fmt.Errorf("build CAR: %w", err)
	}

	// ── 3. Dedup: check existing CAR ─────────────────────────────────
	gateways := opts.GatewayURLs
	existingCAR, carHeight, err := FindExistingCAR(ctx, arw, result.RootCID, gateways)
	if err != nil {
		// Non-fatal: proceed with fresh upload
		existingCAR = ""
	}
	if existingCAR != "" {
		result.DataTXID = existingCAR
		result.DataHeight = carHeight
	} else {
		// ── 4. Upload CAR ────────────────────────────────────────────
		carTags := sdkmeta.BuildCARTags(result.RootCID, result.DataSize)
		arTags := toArweaveTags(carTags)

		tx, status, err := arw.UploadDataChunked(ctx, wallet, carBytes, arTags)
		if err != nil {
			return result, fmt.Errorf("upload CAR: %w", err)
		}
		if tx == nil {
			return result, fmt.Errorf("upload CAR: nil transaction returned")
		}
		result.DataTXID = tx.ID
		if status != nil {
			result.DataHeight = status.BlockHeight
		}
	}

	// ── 5. Build metadata JSON (raw) ─────────────────────────────────
	method := sdkmeta.MethodRaw
	if opts.Bundle {
		method = sdkmeta.MethodBundle
	}

	contentType := detectContentType(filePath)
	originalName := filepath.Base(filePath)

	metaOpts := &sdkmeta.MetaOptions{
		Method:       method,
		ContentType:  contentType,
		OriginalName: originalName,
	}

	metaJSON, err := sdkmeta.BuildMetaJSON(result.RootCID, result.DataTXID, result.DataSize, result.DataHeight, metaOpts)
	if err != nil {
		return result, fmt.Errorf("build metadata: %w", err)
	}

	// ── 6. Dedup: check existing metadata ────────────────────────────
	existingMeta, err := FindExistingMeta(ctx, arw, result.RootCID, result.DataTXID, gateways)
	if err != nil {
		// Non-fatal
		existingMeta = ""
	}
	if existingMeta != "" {
		result.MetaTXID = existingMeta
		return result, nil
	}

	// ── 7. Upload metadata (raw JSON, NOT base64-wrapped) ────────────
	// Note: metadata is uploaded as raw JSON bytes, not base64url-encoded.
	metaTags := sdkmeta.BuildMetaTags(result.RootCID, result.DataTXID)
	arMetaTags := toArweaveTags(metaTags)

	metaTX, _, err := arw.UploadDataChunked(ctx, wallet, metaJSON, arMetaTags)
	if err != nil {
		// Metadata confirmation timeout is non-fatal — save txid and continue
		if metaTX != nil && metaTX.ID != "" {
			result.MetaTXID = metaTX.ID
			return result, nil
		}
		return result, fmt.Errorf("upload metadata: %w", err)
	}
	if metaTX != nil {
		result.MetaTXID = metaTX.ID
	}

	return result, nil
}

// ── Helpers ────────────────────────────────────────────────────────────

// detectContentType returns a MIME type based on file extension.
func detectContentType(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	mimeTypes := map[string]string{
		".jpg": "image/jpeg", ".jpeg": "image/jpeg",
		".png": "image/png", ".gif": "image/gif",
		".webp": "image/webp", ".svg": "image/svg+xml",
		".mp4": "video/mp4", ".webm": "video/webm",
		".mp3": "audio/mpeg", ".wav": "audio/wav",
		".ogg": "audio/ogg", ".flac": "audio/flac",
		".pdf": "application/pdf",
		".json": "application/json", ".xml": "application/xml",
		".html": "text/html", ".htm": "text/html",
		".css": "text/css", ".js": "application/javascript",
		".txt": "text/plain", ".md": "text/markdown",
		".zip": "application/zip", ".tar": "application/x-tar",
		".gz": "application/gzip", ".bz2": "application/x-bzip2",
		".car": "application/vnd.ipld.car",
	}
	if mime, ok := mimeTypes[ext]; ok {
		return mime
	}
	return "application/octet-stream"
}

// toArweaveTags converts SDK metadata tags to arweave tags.
func toArweaveTags(tags []sdkmeta.Tag) []arweave.Tag {
	result := make([]arweave.Tag, len(tags))
	for i, t := range tags {
		result[i] = arweave.Tag{Name: t.Name, Value: t.Value}
	}
	return result
}
