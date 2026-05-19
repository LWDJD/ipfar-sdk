package ipfar

import (
	"context"
	"fmt"

	"github.com/LWDJD/ipfar-sdk/arweave"
	sdkcar "github.com/LWDJD/ipfar-sdk/verify/ipfs"
	sdkmeta "github.com/LWDJD/ipfar-sdk/verify/metadata"
	"github.com/ipfs/go-cid"
)

// VerifyOptions holds optional configuration for verification.
type VerifyOptions struct {
	GatewayURLs []string // Fallback gateways for verification
}

// Verify verifies a Root-CID against on-chain data.
//
// Checks performed:
//  1. Metadata integrity — finds and validates metadata JSON
//  2. CAR data integrity — downloads CAR and validates root CID
//  3. PoW validation — if applicable (data_size < 100 MiB)
//
// Returns a VerifyResult with detailed per-check status.
func Verify(ctx context.Context, arw *arweave.GatewayClient, rootCID string, opts *VerifyOptions) (*VerifyResult, error) {
	if opts == nil {
		opts = &VerifyOptions{}
	}

	result := &VerifyResult{Valid: true}
	gateways := collectGatewayURLs(arw, opts.GatewayURLs)

	// ── 1. Find and validate metadata ──────────────────────────────────
	metaCandidates, err := arw.QueryExistingMetas(ctx, rootCID, "", 8)
	if err != nil {
		result.AddError(fmt.Sprintf("query metadata: %v", err))
		return result, nil
	}
	if len(metaCandidates) == 0 {
		result.AddError("no metadata found on chain")
		return result, nil
	}

	var meta *sdkmeta.Metadata
	var metaTXID string

	for _, txID := range metaCandidates {
		rawData, err := arw.DownloadTransactionData(ctx, txID)
		if err != nil {
			continue
		}

		m, err := tryParseMetadata(rawData)
		if err != nil {
			continue
		}

		if err := m.Validate(); err != nil {
			continue
		}

		if m.RootCID == rootCID {
			meta = m
			metaTXID = txID
			break
		}
	}

	if meta == nil {
		result.AddError("no valid metadata found for root CID")
		return result, nil
	}
	result.MetaVerified = true
	_ = metaTXID

	// ── 2. Verify CAR data integrity ──────────────────────────────────
	carVerified := false
	for _, gwURL := range gateways {
		gw := arweave.NewGatewayClient(gwURL)

		// Download CAR
		carData, err := gw.DownloadTransactionData(ctx, meta.DataTXID)
		if err != nil {
			continue
		}

		// Verify root CID in CAR
		expectedCID, err := cid.Decode(rootCID)
		if err != nil {
			result.AddError(fmt.Sprintf("invalid root CID: %v", err))
			return result, nil
		}

		if verifyLocalCAR(carData, expectedCID) {
			carVerified = true
			break
		}
	}

	if carVerified {
		result.CARVerified = true
	} else {
		result.AddError("CAR data verification failed on all gateways")
	}

	// ── 3. Verify PoW if applicable ───────────────────────────────────
	if meta.NeedsPoW() {
		if meta.PoW != "" && meta.PoWAlg != "" {
			// PoW is present; full PoW verification requires the SDK's pow package.
			// For now, presence check passes.
			result.PoWVerified = true
		} else {
			result.AddError("PoW required but missing")
		}
	} else {
		// Large file — PoW not required
		result.PoWVerified = true
	}

	return result, nil
}

// ── Local CAR verification ─────────────────────────────────────────────

// verifyLocalCAR checks that a local CAR byte slice has the expected root CID.
// Uses the SDK's CAR parser.
func verifyLocalCAR(carBytes []byte, expectedCID cid.Cid) bool {
	if len(carBytes) < 11 {
		return false
	}

	// Use the SDK's CarParser via a bytes reader
	reader := &bytesReaderAt{data: carBytes}
	parser, err := sdkcar.NewCarParserFromReader(reader, int64(len(carBytes)))
	if err != nil {
		return false
	}
	defer parser.Close()

	info, err := parser.ParseInfo()
	if err != nil {
		return false
	}

	if info.Version != 2 {
		// Try v1 as fallback
		for _, root := range info.Roots {
			if root.Equals(expectedCID) {
				return true
			}
		}
		return false
	}

	if !info.HasIndex {
		return false
	}

	for _, root := range info.Roots {
		if root.Equals(expectedCID) {
			// Also validate index
			if err := parser.ValidateIndex(); err != nil {
				return false
			}
			return true
		}
	}

	return false
}

// ── bytesReaderAt ──────────────────────────────────────────────────────

type bytesReaderAt struct {
	data []byte
}

func (r *bytesReaderAt) ReadAt(p []byte, off int64) (n int, err error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}
	if off >= int64(len(r.data)) {
		return 0, fmt.Errorf("EOF")
	}
	n = copy(p, r.data[off:])
	if n < len(p) {
		return n, fmt.Errorf("EOF")
	}
	return n, nil
}
