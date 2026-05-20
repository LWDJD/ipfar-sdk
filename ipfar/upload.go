package ipfar

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/LWDJD/ipfar-sdk/arweave"
	"github.com/LWDJD/ipfar-sdk/bundle"
	"github.com/LWDJD/ipfar-sdk/pow"
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
	if arw == nil {
		return nil, fmt.Errorf("gateway client is nil")
	}
	if opts == nil {
		opts = &UploadOptions{}
	}

	result := &UploadResult{}

	// ── 1. Read file and compute CID ──────────────────────────────────
	fmt.Fprintf(os.Stderr, "   Computing CID...")
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
	fmt.Fprintf(os.Stderr, " done (%s)\n", result.RootCID)

	// ── 2. Dedup / Upload CAR ────────────────────────────────────────
	gateways := opts.GatewayURLs

	if opts.Bundle {
		// Bundle mode: wrap CAR in ANS-104 Bundle
		fmt.Fprintf(os.Stderr, "   Building CAR...")
		carBytes, _, err := BuildCarV2(fileData)
		if err != nil {
			return result, fmt.Errorf("build CAR: %w", err)
		}
		fmt.Fprintf(os.Stderr, " done (%s bytes)\n", formatNumber(len(carBytes)))

		fmt.Fprintf(os.Stderr, "   Building ANS-104 bundle...")
		bundleTXID, bundleHeight, err := uploadAsBundle(ctx, arw, wallet, carBytes, result, gateways)
		if err != nil {
			return result, fmt.Errorf("upload bundle: %w", err)
		}
		result.DataTXID = bundleTXID
		result.DataHeight = bundleHeight
		fmt.Fprintf(os.Stderr, " done (tx=%s, height=%d)\n", shortTXID(bundleTXID), bundleHeight)
	} else {
		// Dedup first: check if CAR already exists on chain before building
		fmt.Fprintf(os.Stderr, "   Checking for existing CAR on chain...")
		existingCAR, carHeight, err := FindExistingCAR(ctx, arw, result.RootCID, gateways)
		if err != nil {
			existingCAR = ""
		}
		if existingCAR != "" {
			result.DataTXID = existingCAR
			result.DataHeight = carHeight
			fmt.Fprintf(os.Stderr, " found (tx=%s, height=%d, reusing)\n", shortTXID(existingCAR), carHeight)
		} else {
			fmt.Fprintf(os.Stderr, " none found (fresh upload)\n")

			// Only build CAR if we actually need to upload
			fmt.Fprintf(os.Stderr, "   Building CAR...")
			carBytes, _, err := BuildCarV2(fileData)
			if err != nil {
				return result, fmt.Errorf("build CAR: %w", err)
			}
			fmt.Fprintf(os.Stderr, " done (%s bytes)\n", formatNumber(len(carBytes)))

			carTags := sdkmeta.BuildCARTags(result.RootCID, result.DataSize)
			arTags := toArweaveTags(carTags)

			fmt.Fprintf(os.Stderr, "   Uploading CAR...")
			tx, status, err := arw.UploadDataChunked(ctx, wallet, carBytes, arTags)
			if err != nil {
				return result, fmt.Errorf("upload CAR: %w", err)
			}
			if tx == nil {
				return result, fmt.Errorf("upload CAR: nil transaction returned")
			}
			result.DataTXID = tx.ID
			if status != nil && status.BlockHeight > 0 {
				result.DataHeight = status.BlockHeight
			} else {
				// Retry getting tx status: 3 attempts, 10s apart.
				// Try primary gateway first, then fallback to ar-io.dev.
				fallbackClients := []*arweave.GatewayClient{
					arw,
					arweave.NewGatewayClient("https://ar-io.dev"),
				}
				var lastErr error
				for i := 0; i < 3; i++ {
					for _, client := range fallbackClients {
						retryStatus, retryErr := client.GetTransactionStatus(ctx, tx.ID)
						if retryErr == nil && retryStatus != nil && retryStatus.BlockHeight > 0 {
							result.DataHeight = retryStatus.BlockHeight
							lastErr = nil
							break
						}
						lastErr = retryErr
						if lastErr == nil {
							lastErr = fmt.Errorf("block height is 0")
						}
					}
					if result.DataHeight > 0 {
						break
					}
					if i < 2 {
						time.Sleep(10 * time.Second)
					}
				}
				if result.DataHeight <= 0 {
					return result, fmt.Errorf("failed to get CAR tx block height after retries (tx=%s)", tx.ID)
				}
			}
			fmt.Fprintf(os.Stderr, " done (tx=%s, height=%d)\n", shortTXID(tx.ID), result.DataHeight)
		}
	}

	// ── 5. Build metadata JSON (raw) ─────────────────────────────────
	method := sdkmeta.MethodRaw
	if opts.Bundle {
		method = sdkmeta.MethodBundle
	}

	// ── 5a. Compute PoW if required (data_size < 100 MiB) ─────────────
	var powSalt, powAlg string
	if result.DataSize < sdkmeta.PoWThreshold {
		workers := opts.PoWWorkers
		if workers <= 0 {
			workers = pow.DefaultWorkers()
		}
		fmt.Fprintf(os.Stderr, "   Computing PoW (%d workers)...", workers)
		powSalt, err = pow.ComputePoW(ctx, result.RootCID, result.DataTXID, workers, nil)
		if err != nil {
			return result, fmt.Errorf("compute PoW: %w", err)
		}
		powAlg = pow.Algorithm
		fmt.Fprintf(os.Stderr, " done (salt=%s)\n", truncateSalt(powSalt))
	}

	contentType := detectContentType(filePath)
	originalName := filepath.Base(filePath)

	metaOpts := &sdkmeta.MetaOptions{
		Method:       method,
		ContentType:  contentType,
		OriginalName: originalName,
		PoW:          powSalt,
		PoWAlg:       powAlg,
	}
	if opts.Bundle {
		metaOpts.BundleTXID = result.DataTXID
	}

	fmt.Fprintf(os.Stderr, "   Building metadata...")
	metaJSON, err := sdkmeta.BuildMetaJSON(result.RootCID, result.DataTXID, result.DataSize, result.DataHeight, metaOpts)
	if err != nil {
		return result, fmt.Errorf("build metadata: %w", err)
	}
	fmt.Fprintf(os.Stderr, " done\n")

	// ── 6. Dedup: check existing metadata ────────────────────────────
	fmt.Fprintf(os.Stderr, "   Checking for existing metadata...")
	existingMeta, err := FindExistingMeta(ctx, arw, result.RootCID, result.DataTXID, gateways)
	if err != nil {
		// Non-fatal
		existingMeta = ""
	}
	if existingMeta != "" {
		result.MetaTXID = existingMeta
		fmt.Fprintf(os.Stderr, " found (tx=%s, reusing)\n", shortTXID(existingMeta))
		fmt.Fprintf(os.Stderr, "   ✅ Upload complete\n")
		return result, nil
	}
	fmt.Fprintf(os.Stderr, " none found (fresh upload)\n")

	// ── 7. Upload metadata (raw JSON, NOT base64-wrapped) ────────────
	// Note: metadata is uploaded as raw JSON bytes, not base64url-encoded.
	metaTags := sdkmeta.BuildMetaTags(result.RootCID, result.DataTXID)
	arMetaTags := toArweaveTags(metaTags)

	fmt.Fprintf(os.Stderr, "   Uploading metadata...")
	metaTX, _, err := arw.UploadDataChunked(ctx, wallet, metaJSON, arMetaTags)
	if err != nil {
		// Metadata confirmation timeout is non-fatal — save txid and continue
		if metaTX != nil && metaTX.ID != "" {
			result.MetaTXID = metaTX.ID
			fmt.Fprintf(os.Stderr, " done (tx=%s)\n", shortTXID(metaTX.ID))
			fmt.Fprintf(os.Stderr, "   ✅ Upload complete\n")
			return result, nil
		}
		return result, fmt.Errorf("upload metadata: %w", err)
	}
	if metaTX != nil {
		result.MetaTXID = metaTX.ID
	}
	fmt.Fprintf(os.Stderr, " done (tx=%s)\n", shortTXID(result.MetaTXID))
	fmt.Fprintf(os.Stderr, "   ✅ Upload complete\n")

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

// formatNumber formats an int with comma separators.
func formatNumber(n int) string {
	s := fmt.Sprintf("%d", n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// shortTXID returns a short representation of a TXID (first 7 chars + "...")
func shortTXID(txid string) string {
	if len(txid) <= 10 {
		return txid
	}
	return txid[:7] + "..."
}

// truncateSalt returns a short representation of a PoW salt (first 8 chars + "...")
func truncateSalt(salt string) string {
	if len(salt) <= 10 {
		return salt
	}
	return salt[:8] + "..."
}

// uploadAsBundle wraps CAR bytes in an ANS-104 Bundle and uploads it.
// Returns the bundle transaction ID and block height.
func uploadAsBundle(ctx context.Context, arw *arweave.GatewayClient, wallet *arweave.Wallet, carBytes []byte, result *UploadResult, gateways []string) (string, int, error) {
	// 1. Create ANS-104 DataItem with CAR bytes
	item := bundle.NewDataItem()
	item.SetData(carBytes)

	// Set CAR tags on the data item
	carTags := sdkmeta.BuildCARTags(result.RootCID, result.DataSize)
	for _, t := range carTags {
		item.AddTag(t.Name, t.Value)
	}

	// 2. Sign the data item with wallet's RSA key
	if err := item.SignWithRSA(wallet.PrivateKey); err != nil {
		return "", 0, fmt.Errorf("sign data item: %w", err)
	}

	// 3. Build the bundle
	builder := bundle.NewBundleBuilder()
	builder.AddItem(item)
	bundleBytes, err := builder.Build()
	if err != nil {
		return "", 0, fmt.Errorf("build bundle: %w", err)
	}

	// 4. Upload the bundle as a raw transaction
	bundleTags := []arweave.Tag{
		{Name: "Protocol", Value: "IPFS-Arweave-Bridge"},
		{Name: "Protocol-Version", Value: "1"},
		{Name: "Content-Type", Value: "application/octet-stream"},
		{Name: "Bundle-Format", Value: "ans-104"},
		{Name: "Root-CID", Value: result.RootCID},
	}

	tx, status, err := arw.UploadDataRaw(ctx, wallet, bundleBytes, bundleTags)
	if err != nil {
		return "", 0, fmt.Errorf("upload bundle tx: %w", err)
	}
	if tx == nil {
		return "", 0, fmt.Errorf("upload bundle: nil transaction returned")
	}

	height := 0
	if status != nil {
		height = status.BlockHeight
	}

	return tx.ID, height, nil
}
