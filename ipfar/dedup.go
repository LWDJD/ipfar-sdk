package ipfar

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/LWDJD/ipfar-sdk/arweave"
	sdkcar "github.com/LWDJD/ipfar-sdk/verify/ipfs"
	"github.com/ipfs/go-cid"
)

// DefaultFallbackGateways are public Arweave gateways tried when the primary
// gateway fails to serve data. The list is deduplicated at runtime.
var DefaultFallbackGateways = []string{
	"https://ar-io.dev",
	"https://arweave.net",
}

// FindExistingCAR queries Arweave for an existing CAR transaction with the
// given Root-CID.  Returns the txid and block height if found and verified,
// or an empty string and 0 if no valid match exists.
//
// Multi-gateway verification is attempted using the provided gateways list
// (falling back to DefaultFallbackGateways if empty).
func FindExistingCAR(ctx context.Context, arw *arweave.GatewayClient, rootCID string, gateways []string) (string, int, error) {
	candidates, err := arw.QueryExistingCARs(ctx, rootCID, 8)
	if err != nil {
		return "", 0, fmt.Errorf("dedup query failed: %w", err)
	}
	if len(candidates) == 0 {
		return "", 0, nil
	}

	gwURLs := collectGatewayURLs(arw, gateways)

	for _, txID := range candidates {
		verified, height := verifyRemoteCAR(ctx, arw, txID, rootCID, gwURLs)
		if verified {
			return txID, height, nil
		}
	}

	return "", 0, nil
}

// FindExistingMeta queries Arweave for an existing metadata transaction
// matching the given rootCID and dataTXID.  Returns the txid if found and
// verified, or an empty string if no valid match exists.
func FindExistingMeta(ctx context.Context, arw *arweave.GatewayClient, rootCID, dataTXID string, gateways []string) (string, error) {
	candidates, err := arw.QueryExistingMetas(ctx, rootCID, dataTXID, 8)
	if err != nil {
		return "", fmt.Errorf("metadata dedup query failed: %w", err)
	}
	if len(candidates) == 0 {
		return "", nil
	}

	gwURLs := collectGatewayURLs(arw, gateways)

	for _, txID := range candidates {
		if verifyRemoteMeta(ctx, arw, txID, rootCID, dataTXID, gwURLs) {
			return txID, nil
		}
	}

	return "", nil
}

// ── Internal verification helpers ──────────────────────────────────────

// verifyRemoteCAR downloads key portions of a remote CAR and validates it.
// Tries multiple gateways; returns (true, height) on first success.
func verifyRemoteCAR(ctx context.Context, primary *arweave.GatewayClient, txID, expectedRootCID string, gwURLs []string) (bool, int) {
	expectedCID, err := cid.Decode(expectedRootCID)
	if err != nil {
		return false, 0
	}

	for _, gwURL := range gwURLs {
		gw := arweave.NewGatewayClient(gwURL)

		fileSize, err := gw.GetTransactionDataSize(ctx, txID)
		if err != nil {
			continue
		}

		// Create a CAR parser backed by the remote gateway.
		// For simplicity we download the first ~200 bytes to verify header + roots.
		reader := newRemoteCarReader(ctx, gw, txID, fileSize)
		parser, err := sdkcar.NewCarParserFromReader(reader, fileSize)
		if err != nil {
			continue
		}

		info, err := parser.ParseInfo()
		parser.Close()
		if err != nil {
			continue
		}

		if info.Version != 2 {
			continue
		}
		if !info.HasIndex {
			continue
		}

		found := false
		for _, root := range info.Roots {
			if root.Equals(expectedCID) {
				found = true
				break
			}
		}
		if !found {
			continue
		}

		// Get block height
		status, err := gw.GetTransactionStatus(ctx, txID)
		if err != nil || status == nil {
			continue
		}

		return true, status.BlockHeight
	}

	return false, 0
}

// verifyRemoteMeta downloads and validates remote metadata.
// The remote data may be plain JSON or base64url-encoded.
func verifyRemoteMeta(ctx context.Context, primary *arweave.GatewayClient, txID, expectedRootCID, expectedDataTXID string, gwURLs []string) bool {
	type metaFields struct {
		RootCID  string `json:"root_cid"`
		DataTXID string `json:"data_txid"`
	}

	for _, gwURL := range gwURLs {
		gw := arweave.NewGatewayClient(gwURL)

		rawData, err := gw.DownloadTransactionData(ctx, txID)
		if err != nil {
			continue
		}

		var mf metaFields

		// Try plain JSON first
		if json.Unmarshal(rawData, &mf) == nil {
			if mf.RootCID == expectedRootCID && mf.DataTXID == expectedDataTXID {
				return true
			}
			continue
		}

		// Try base64url decode
		decoded, err := base64.RawURLEncoding.DecodeString(string(rawData))
		if err != nil {
			decoded, err = base64.StdEncoding.DecodeString(string(rawData))
		}
		if err != nil {
			continue
		}

		if json.Unmarshal(decoded, &mf) != nil {
			continue
		}
		if mf.RootCID == expectedRootCID && mf.DataTXID == expectedDataTXID {
			return true
		}
	}

	return false
}

// ── remoteCarReader implements io.ReaderAt over HTTP range requests ────

type remoteCarReader struct {
	gateway *arweave.GatewayClient
	txID    string
	size    int64
	ctx     context.Context
}

func newRemoteCarReader(ctx context.Context, gateway *arweave.GatewayClient, txID string, size int64) *remoteCarReader {
	return &remoteCarReader{
		gateway: gateway,
		txID:    txID,
		size:    size,
		ctx:     ctx,
	}
}

func (r *remoteCarReader) ReadAt(p []byte, off int64) (n int, err error) {
	if off >= r.size {
		return 0, fmt.Errorf("EOF")
	}

	end := off + int64(len(p)) - 1
	if end >= r.size {
		end = r.size - 1
	}

	data, err := r.gateway.DownloadTransactionData(r.ctx, r.txID)
	if err != nil {
		return 0, err
	}

	// Simple approach: download full data and slice
	if off >= int64(len(data)) {
		return 0, fmt.Errorf("EOF")
	}
	endIdx := int(end) + 1
	if endIdx > len(data) {
		endIdx = len(data)
	}
	n = copy(p, data[off:endIdx])
	if off+int64(n) >= r.size {
		return n, fmt.Errorf("EOF")
	}
	return n, nil
}

// ── Gateway URL collection ─────────────────────────────────────────────

// collectGatewayURLs returns a deduplicated list of gateway URLs.
func collectGatewayURLs(primary *arweave.GatewayClient, extra []string) []string {
	seen := make(map[string]bool)
	var urls []string

	primaryURL := strings.TrimRight(primary.GatewayURL, "/")
	seen[primaryURL] = true
	urls = append(urls, primaryURL)

	all := append(extra, DefaultFallbackGateways...)
	for _, u := range all {
		u = strings.TrimRight(u, "/")
		if !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
	}
	return urls
}
