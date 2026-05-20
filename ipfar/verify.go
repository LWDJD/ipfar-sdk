package ipfar

import (
	"context"
	"fmt"

	"github.com/LWDJD/ipfar-sdk/arweave"
	sdkcar "github.com/LWDJD/ipfar-sdk/verify/ipfs"
	sdkmeta "github.com/LWDJD/ipfar-sdk/verify/metadata"
	"github.com/ipfs/go-cid"
)

// VerifyProgressFn is called for each verification step.
// step: 1-based current step, total: total number of steps,
// name: step name, details: individual check lines, ok: step passed.
type VerifyProgressFn func(step, total int, name string, details []string, ok bool)

// VerifyOptions holds optional configuration for verification.
type VerifyOptions struct {
	GatewayURLs  []string         // Fallback gateways for verification
	MetadataTXID string           // If set, verify this specific metadata tx directly (skip GraphQL)
	Progress     VerifyProgressFn // Optional progress callback for verbose output
}

// Verify verifies a Root-CID against on-chain data.
//
// Checks performed:
//  1. Metadata integrity — finds and validates metadata JSON
//  2. Tags validation — verifies all required tags
//  3. Block height validation — data_height must be > 0 (or -1 for bundle)
//  4. CAR transaction existence — verifies data_txid is on-chain
//  5. Bundle transaction existence — verifies bundle_txid if present
//  6. CAR data integrity — downloads CAR and validates root CID
//  7. PoW validation — if applicable (data_size < 100 MiB)
//
// Returns a VerifyResult with detailed per-check status.
func Verify(ctx context.Context, arw *arweave.GatewayClient, rootCID string, opts *VerifyOptions) (*VerifyResult, error) {
	if opts == nil {
		opts = &VerifyOptions{}
	}

	result := &VerifyResult{Valid: true}

	// ── Direct metadata TXID path (skip GraphQL) ──────────────────────
	if opts.MetadataTXID != "" {
		return verifyWithMetadataTXID(ctx, arw, rootCID, opts, result)
	}

	// ── GraphQL query path (original) ─────────────────────────────────
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

	// ── 2. Verify metadata transaction tags ──────────────────────────
	if tags, err := arw.GetTransactionTags(ctx, metaTXID); err == nil {
		metaTags := make([]sdkmeta.Tag, len(tags))
		for i, t := range tags {
			metaTags[i] = sdkmeta.Tag{Name: t.Name, Value: t.Value}
		}
		if err := sdkmeta.ValidateTags(metaTags); err != nil {
			result.AddError(fmt.Sprintf("metadata tags: %v", err))
		}
	} else {
		result.AddError(fmt.Sprintf("get metadata tags: %v", err))
	}

	// ── 3. Block height validation ───────────────────────────────────
	if err := validateBlockHeight(meta); err != nil {
		result.AddError(fmt.Sprintf("block height: %v", err))
	}

	// ── 4. Bundle txid verification ──────────────────────────────────
	if meta.BundleTXID != "" {
		if _, err := arw.GetTransactionStatus(ctx, meta.BundleTXID); err != nil {
			result.AddError(fmt.Sprintf("bundle_txid %s: %v", meta.BundleTXID, err))
		}
	}

	// ── 5. Data txid verification ────────────────────────────────────
	status, err := arw.GetTransactionStatus(ctx, meta.DataTXID)
	if err != nil {
		result.AddError(fmt.Sprintf("data_txid %s: %v", meta.DataTXID, err))
	} else if !status.Confirmed {
		result.AddError(fmt.Sprintf("data_txid %s: transaction not confirmed", meta.DataTXID))
	} else if status.BlockHeight > 0 && meta.DataHeight > 0 && status.BlockHeight != meta.DataHeight {
		result.AddError(fmt.Sprintf("data_height mismatch: on-chain=%d, metadata=%d", status.BlockHeight, meta.DataHeight))
	}

	// ── 6. Verify CAR data integrity ──────────────────────────────────
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

	// ── 7. Verify PoW if applicable ───────────────────────────────────
	if meta.NeedsPoW() {
		if meta.PoW != "" && meta.PoWAlg != "" {
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

// ── Direct metadata TXID verification ──────────────────────────────────

// verifyWithMetadataTXID verifies using a specific metadata transaction ID,
// bypassing the GraphQL query.  This is useful when GraphQL is unavailable
// or the caller already knows the exact metadata transaction.
func verifyWithMetadataTXID(ctx context.Context, arw *arweave.GatewayClient, rootCID string, opts *VerifyOptions, result *VerifyResult) (*VerifyResult, error) {
	totalSteps := 7
	step := 0

	// ── Step 1: Download metadata ─────────────────────────────────────
	step++
	metaData, err := DownloadRaw(ctx, arw, opts.MetadataTXID)
	if err != nil {
		reportProgress(opts, step, totalSteps, "Downloading metadata", nil, false)
		result.AddError(fmt.Sprintf("download metadata %s: %v", opts.MetadataTXID, err))
		return result, nil
	}
	reportProgress(opts, step, totalSteps, "Downloading metadata",
		[]string{fmt.Sprintf("%d bytes", len(metaData))}, true)

	// ── Step 2: Parse metadata ────────────────────────────────────────
	step++
	meta, err := tryParseMetadata(metaData)
	if err != nil {
		reportProgress(opts, step, totalSteps, "Parsing metadata JSON", nil, false)
		result.AddError(fmt.Sprintf("parse metadata %s: %v", opts.MetadataTXID, err))
		return result, nil
	}
	reportProgress(opts, step, totalSteps, "Parsing metadata JSON", nil, true)

	// ── Step 3: Validate metadata fields ────────────────────────────
	step++
	fieldResults := validateMetadataFields(meta)
	var fieldDetails []string
	allOK := true
	for _, fr := range fieldResults {
		mark := "✓"
		if !fr.OK {
			mark = "✗"
			allOK = false
			result.AddError(fmt.Sprintf("metadata.%s: %s", fr.Field, fr.Error))
		}
		detail := fmt.Sprintf("%s: %s %s", fr.Field, truncateForDisplay(fr.Value, 40), mark)
		if fr.Note != "" {
			detail += " (" + fr.Note + ")"
		}
		fieldDetails = append(fieldDetails, detail)
	}
	if !allOK {
		fieldDetails = append(fieldDetails, fmt.Sprintf("FAIL: %d field(s) invalid", countFieldErrors(fieldResults)))
	}
	reportProgress(opts, step, totalSteps, "Validating metadata fields", fieldDetails, allOK)
	if allOK {
		result.MetaVerified = true
	}

	// Verify root_cid matches (non-fatal: continue checking)
	if meta.RootCID != rootCID {
		result.AddError(fmt.Sprintf("root_cid mismatch: metadata has %s, expected %s", meta.RootCID, rootCID))
	}

	// ── Step 4: Verify Tags ───────────────────────────────────────────
	step++
	var tagDetails []string
	tagsOK := true
	if tags, err := arw.GetTransactionTags(ctx, opts.MetadataTXID); err != nil {
		tagDetails = []string{fmt.Sprintf("ERROR: %v", err)}
		tagsOK = false
		result.AddError(fmt.Sprintf("metadata tags: %v", err))
	} else {
		// Convert arweave.Tag → sdkmeta.Tag
		metaTags := make([]sdkmeta.Tag, len(tags))
		for i, t := range tags {
			metaTags[i] = sdkmeta.Tag{Name: t.Name, Value: t.Value}
		}
		if err := sdkmeta.ValidateTags(metaTags); err != nil {
			tagDetails = append(tagDetails, fmt.Sprintf("ERROR: %v", err))
			tagsOK = false
			result.AddError(fmt.Sprintf("metadata tags: %v", err))
		} else {
			// Report each tag with checkmark
			tagMap := make(map[string]string)
			for _, t := range tags {
				tagMap[t.Name] = t.Value
			}
			requiredTags := []string{"Protocol", "Protocol-Version", "IPFAR-Type", "Root-CID", "Content-Type", "Data-TXID"}
			for _, name := range requiredTags {
				val, ok := tagMap[name]
				if ok {
					tagDetails = append(tagDetails, fmt.Sprintf("%s: %s ✓", name, truncateForDisplay(val, 40)))
				} else {
					tagDetails = append(tagDetails, fmt.Sprintf("%s: MISSING ✗", name))
					tagsOK = false
				}
			}
		}
	}
	reportProgress(opts, step, totalSteps, "Verifying Tags", tagDetails, tagsOK)

	// ── Block height validation ──────────────────────────────────────
	if err := validateBlockHeight(meta); err != nil {
		result.AddError(fmt.Sprintf("block height: %v", err))
	}

	// ── Bundle txid verification ─────────────────────────────────────
	if meta.BundleTXID != "" {
		bundleStatus, err := arw.GetTransactionStatus(ctx, meta.BundleTXID)
		if err != nil {
			result.AddError(fmt.Sprintf("bundle_txid %s: %v", meta.BundleTXID, err))
		} else if !bundleStatus.Confirmed {
			result.AddError(fmt.Sprintf("bundle_txid %s: transaction not confirmed", meta.BundleTXID))
		}
	}

	// ── Step 5: Check CAR transaction ─────────────────────────────────
	step++
	var carTxDetails []string
	carTxOK := true
	status, err := arw.GetTransactionStatus(ctx, meta.DataTXID)
	if err != nil {
		carTxDetails = []string{fmt.Sprintf("ERROR: %v", err)}
		carTxOK = false
		result.AddError(fmt.Sprintf("data_txid %s: %v", meta.DataTXID, err))
	} else if !status.Confirmed {
		carTxDetails = []string{"ERROR: transaction not confirmed"}
		carTxOK = false
		result.AddError(fmt.Sprintf("data_txid %s: transaction not confirmed", meta.DataTXID))
	} else {
		carTxDetails = append(carTxDetails,
			fmt.Sprintf("Height: %d, Confirmations: available ✓", status.BlockHeight))
		if meta.DataHeight > 0 {
			if status.BlockHeight == meta.DataHeight {
				carTxDetails = append(carTxDetails,
					fmt.Sprintf("data_height match: %d = %d ✓", status.BlockHeight, meta.DataHeight))
			} else {
				carTxDetails = append(carTxDetails,
					fmt.Sprintf("data_height mismatch: on-chain=%d, metadata=%d ✗", status.BlockHeight, meta.DataHeight))
				carTxOK = false
				result.AddError(fmt.Sprintf("data_height mismatch: on-chain=%d, metadata=%d", status.BlockHeight, meta.DataHeight))
			}
		}
	}
	reportProgress(opts, step, totalSteps,
		fmt.Sprintf("Checking CAR transaction (%s)", truncateForDisplay(meta.DataTXID, 16)),
		carTxDetails, carTxOK)

	// ── Step 6: Download CAR data ─────────────────────────────────────
	step++
	gateways := collectGatewayURLs(arw, opts.GatewayURLs)
	carVerified := false
	var carDetails []string
	for _, gwURL := range gateways {
		gw := arweave.NewGatewayClient(gwURL)
		carData, err := gw.DownloadTransactionData(ctx, meta.DataTXID)
		if err != nil {
			continue
		}

		expectedCID, err := cid.Decode(rootCID)
		if err != nil {
			carDetails = []string{fmt.Sprintf("ERROR: invalid root CID: %v", err)}
			result.AddError(fmt.Sprintf("invalid root CID: %v", err))
			reportProgress(opts, step, totalSteps, "Downloading CAR data", carDetails, false)
			return result, nil
		}

		carDetails = append(carDetails,
			fmt.Sprintf("%s bytes", formatNumber(len(carData))))

		if verifyLocalCAR(carData, expectedCID) {
			carVerified = true
			carDetails = append(carDetails,
				fmt.Sprintf("Root CID match: %s ✓", truncateForDisplay(rootCID, 40)))
			break
		}
		carDetails = append(carDetails, "Root CID mismatch ✗")
	}

	if carVerified {
		result.CARVerified = true
	} else if len(carDetails) == 0 {
		carDetails = []string{"ERROR: all gateways failed"}
		result.AddError("CAR data verification failed on all gateways")
	}
	reportProgress(opts, step, totalSteps, "Downloading CAR data", carDetails, carVerified)

	// ── Step 7: Verify PoW ────────────────────────────────────────────
	step++
	var powDetails []string
	powOK := true
	if meta.NeedsPoW() {
		if meta.PoW != "" && meta.PoWAlg != "" {
			powDetails = []string{
				fmt.Sprintf("salt=%s, alg=%s ✓",
					truncateForDisplay(meta.PoW, 24),
					truncateForDisplay(meta.PoWAlg, 32)),
			}
			result.PoWVerified = true
		} else {
			powDetails = []string{"ERROR: PoW required but missing ✗"}
			powOK = false
			result.AddError("PoW required but missing")
		}
	} else {
		powDetails = []string{"Skipped (file >= 100 MiB, PoW not required) ✓"}
		result.PoWVerified = true
	}
	reportProgress(opts, step, totalSteps, "Verifying PoW", powDetails, powOK)

	return result, nil
}

// ── Helpers ────────────────────────────────────────────────────────────

// reportProgress calls the progress callback if set.
func reportProgress(opts *VerifyOptions, step, total int, name string, details []string, ok bool) {
	if opts != nil && opts.Progress != nil {
		opts.Progress(step, total, name, details, ok)
	}
}

// validateBlockHeight checks that data_height is valid:
// must be >= -1 (0 is allowed, e.g. genesis block; -1 for bundle).
// Note: data_height = 0 is technically valid but warrants a warning
// as it typically indicates an unknown or genesis height.
func validateBlockHeight(meta *sdkmeta.Metadata) error {
	if meta.DataHeight < -1 {
		return fmt.Errorf("invalid data_height: %d (must be >= -1)", meta.DataHeight)
	}
	if meta.DataHeight == -1 && meta.Method != sdkmeta.MethodBundle {
		return fmt.Errorf("data_height is -1 but method is not bundle")
	}
	// data_height = 0 is allowed (genesis / unknown height)
	return nil
}

// truncateForDisplay truncates a string for display purposes.
func truncateForDisplay(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// ── Field-level metadata validation ──────────────────────────────────

// fieldResult holds the validation result for a single metadata field.
type fieldResult struct {
	Field string // field name (e.g. "version", "root_cid")
	Value string // display value (truncated for readability)
	OK    bool   // whether the field passed validation
	Error string // error message if not OK
	Note  string // optional extra note (e.g. "must be 1")
}

// validateMetadataFields checks each metadata field individually and
// returns a slice of results.  Unlike Validate(), this checks ALL fields
// and returns multiple errors so the caller can display all problems at once.
func validateMetadataFields(meta *sdkmeta.Metadata) []fieldResult {
	var results []fieldResult

	// --- version ---
	fv := fmt.Sprintf("%d", meta.Version)
	if meta.Version == 0 {
		results = append(results, fieldResult{Field: "version", Value: fv, OK: false, Error: "missing version", Note: "must be 1"})
	} else if meta.Version != 1 {
		results = append(results, fieldResult{Field: "version", Value: fv, OK: false, Error: fmt.Sprintf("must be 1, got %d", meta.Version), Note: "must be 1"})
	} else {
		results = append(results, fieldResult{Field: "version", Value: fv, OK: true, Note: "must be 1"})
	}

	// --- method ---
	mv := meta.Method
	if mv == "" {
		results = append(results, fieldResult{Field: "method", Value: "(empty)", OK: false, Error: "missing method", Note: `must be "raw" or "bundle"`})
	} else if mv != sdkmeta.MethodRaw && mv != sdkmeta.MethodBundle {
		results = append(results, fieldResult{Field: "method", Value: mv, OK: false, Error: fmt.Sprintf(`must be "raw" or "bundle", got %q`, mv), Note: `must be "raw" or "bundle"`})
	} else {
		results = append(results, fieldResult{Field: "method", Value: mv, OK: true, Note: `must be "raw" or "bundle"`})
	}

	// --- root_cid ---
	rc := meta.RootCID
	if rc == "" {
		results = append(results, fieldResult{Field: "root_cid", Value: "(empty)", OK: false, Error: "missing root_cid", Note: "valid CID v1 format"})
	} else if !isValidCIDStringMeta(rc) {
		results = append(results, fieldResult{Field: "root_cid", Value: truncateForDisplay(rc, 40), OK: false, Error: fmt.Sprintf("invalid CID: %s", truncateForDisplay(rc, 40)), Note: "valid CID v1 format"})
	} else {
		results = append(results, fieldResult{Field: "root_cid", Value: truncateForDisplay(rc, 40), OK: true, Note: "valid CID v1 format"})
	}

	// --- data_txid ---
	dt := meta.DataTXID
	if dt == "" {
		results = append(results, fieldResult{Field: "data_txid", Value: "(empty)", OK: false, Error: "missing data_txid", Note: "valid Arweave txid, 43 chars base64url"})
	} else if !isValidTXIDStringMeta(dt) {
		results = append(results, fieldResult{Field: "data_txid", Value: truncateForDisplay(dt, 40), OK: false, Error: fmt.Sprintf("invalid txid: %s", truncateForDisplay(dt, 40)), Note: "valid Arweave txid, 43 chars base64url"})
	} else {
		results = append(results, fieldResult{Field: "data_txid", Value: truncateForDisplay(dt, 40), OK: true, Note: "valid Arweave txid, 43 chars base64url"})
	}

	// --- data_height ---
	dh := meta.DataHeight
	dhStr := fmt.Sprintf("%d", dh)
	if dh < -1 {
		results = append(results, fieldResult{Field: "data_height", Value: dhStr, OK: false, Error: fmt.Sprintf("invalid height: %d", dh), Note: ">= -1, valid block height (or -1 for bundle)"})
	} else if dh == 0 {
		results = append(results, fieldResult{Field: "data_height", Value: dhStr, OK: true, Note: "genesis / unknown height (0)"})
	} else if dh == -1 {
		if meta.Method == sdkmeta.MethodBundle {
			results = append(results, fieldResult{Field: "data_height", Value: dhStr, OK: true, Note: "bundle mode (-1)"})
			// bundle_txid must be "none" when data_height = -1
			if meta.BundleTXID != "none" {
				results = append(results, fieldResult{Field: "bundle_txid", Value: truncateForDisplay(meta.BundleTXID, 40), OK: false, Error: fmt.Sprintf("bundle_txid must be \"none\" when data_height = -1, got %q", meta.BundleTXID), Note: "must be \"none\""})
			}
		} else {
			results = append(results, fieldResult{Field: "data_height", Value: dhStr, OK: false, Error: "data_height is -1 but method is not bundle", Note: "> 0 for raw, or -1 for bundle"})
		}
	} else {
		results = append(results, fieldResult{Field: "data_height", Value: dhStr, OK: true, Note: "> 0, valid block height"})
	}

	// --- data_size ---
	ds := meta.DataSize
	dsStr := formatSize(ds)
	if ds <= 0 {
		results = append(results, fieldResult{Field: "data_size", Value: fmt.Sprintf("%d", ds), OK: false, Error: fmt.Sprintf("invalid size: %d", ds), Note: "> 0"})
	} else {
		results = append(results, fieldResult{Field: "data_size", Value: dsStr, OK: true, Note: "> 0"})
	}

	// --- pow (conditional) ---
	pv := meta.PoW
	if meta.NeedsPoW() {
		if pv == "" {
			results = append(results, fieldResult{Field: "pow", Value: "(missing)", OK: false, Error: "missing/invalid pow for small file", Note: "required when data_size < 100 MiB"})
		} else if !isDecimalString(pv) {
			results = append(results, fieldResult{Field: "pow", Value: truncateForDisplay(pv, 24), OK: false, Error: "invalid pow: not a decimal number", Note: "valid uint64 decimal string"})
		} else {
			results = append(results, fieldResult{Field: "pow", Value: truncateForDisplay(pv, 24), OK: true, Note: "valid uint64 decimal string"})
		}
	} else {
		if pv != "" {
			results = append(results, fieldResult{Field: "pow", Value: truncateForDisplay(pv, 24), OK: true, Note: "present (file >= 100 MiB, not required)"})
		} else {
			results = append(results, fieldResult{Field: "pow", Value: "(none)", OK: true, Note: "skipped (file >= 100 MiB)"})
		}
	}

	// --- pow_alg (conditional) ---
	pa := meta.PoWAlg
	if meta.NeedsPoW() {
		if pa == "" {
			results = append(results, fieldResult{Field: "pow_alg", Value: "(missing)", OK: false, Error: "missing pow_alg", Note: "must be \"argon2id-light-v1\""})
		} else if pa != "argon2id-light-v1" {
			results = append(results, fieldResult{Field: "pow_alg", Value: pa, OK: false, Error: fmt.Sprintf("unknown algorithm: %s", pa), Note: "must be \"argon2id-light-v1\""})
		} else {
			results = append(results, fieldResult{Field: "pow_alg", Value: pa, OK: true, Note: "matches known algorithm"})
		}
	} else {
		if pa != "" {
			results = append(results, fieldResult{Field: "pow_alg", Value: pa, OK: true, Note: "present (file >= 100 MiB)"})
		} else {
			results = append(results, fieldResult{Field: "pow_alg", Value: "(none)", OK: true, Note: "skipped (file >= 100 MiB)"})
		}
	}

	// --- bundle_txid (conditional) ---
	bt := meta.BundleTXID
	if meta.Method == sdkmeta.MethodBundle {
		if bt == "" {
			results = append(results, fieldResult{Field: "bundle_txid", Value: "(missing)", OK: false, Error: "missing bundle_txid for bundle method", Note: "required when method=bundle"})
		} else {
			results = append(results, fieldResult{Field: "bundle_txid", Value: truncateForDisplay(bt, 40), OK: true, Note: "present"})
		}
	} else {
		if bt != "" {
			results = append(results, fieldResult{Field: "bundle_txid", Value: truncateForDisplay(bt, 40), OK: true, Note: "present (raw mode, optional)"})
		}
		// else: not present in raw mode, which is fine, no line printed
	}

	// --- content_type (optional) ---
	ct := meta.ContentType
	if ct != "" {
		results = append(results, fieldResult{Field: "content_type", Value: truncateForDisplay(ct, 40), OK: true, Note: "optional"})
	}

	// --- original_name (optional) ---
	on := meta.OriginalName
	if on != "" {
		results = append(results, fieldResult{Field: "original_name", Value: truncateForDisplay(on, 40), OK: true, Note: "optional"})
	}

	return results
}

// countFieldErrors counts the number of field results that are not OK.
func countFieldErrors(results []fieldResult) int {
	n := 0
	for _, fr := range results {
		if !fr.OK {
			n++
		}
	}
	return n
}

// isValidCIDStringMeta checks if a string looks like a valid CID.
func isValidCIDStringMeta(cid string) bool {
	if len(cid) < 10 || len(cid) > 512 {
		return false
	}
	for _, c := range cid {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

// isValidTXIDStringMeta checks if a string looks like a valid Arweave txid.
func isValidTXIDStringMeta(txid string) bool {
	if len(txid) < 10 || len(txid) > 128 {
		return false
	}
	for _, c := range txid {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// isDecimalString checks if a string is a valid unsigned decimal integer.
func isDecimalString(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// formatSize formats a byte count as a human-readable string.
func formatSize(bytes int) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}
	if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024.0)
	}
	if bytes < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1024.0*1024.0))
	}
	return fmt.Sprintf("%.1f GB", float64(bytes)/(1024.0*1024.0*1024.0))
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

	// CAR v1 is not supported — spec §3.1 requires CAR v2
	if info.Version != 2 {
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
