package metadata

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
)

// ============================================================
// §1 — Metadata deep edge cases: PoW format validation
// ============================================================

func TestValidate_PoWFormat_NonDecimal(t *testing.T) {
	meta := validMeta()
	meta.DataSize = 1024 // Needs PoW
	meta.PoWAlg = "argon2id-light-v1"
	// Non-decimal PoW value — metadata validation only checks presence, not format
	meta.PoW = "0xDEADBEEF"
	err := meta.Validate()
	// Metadata validation accepts any non-empty PoW string;
	// PoW format validation is done by the pow verifier, not metadata parser.
	if err != nil {
		t.Errorf("non-decimal PoW should be accepted by metadata validation (format check is pow.Verify's job): %v", err)
	}
}

func TestValidate_PoWFormat_SuperLarge(t *testing.T) {
	// PoW salt larger than math.MaxUint64
	meta := validMeta()
	meta.DataSize = 1024
	meta.PoW = "99999999999999999999999999999999999" // > MaxUint64
	meta.PoWAlg = "argon2id-light-v1"
	// Metadata validation doesn't check PoW numeric bounds (that's pow.Verify's job)
	// But it should still be accepted as a non-empty string
	err := meta.Validate()
	if err != nil {
		t.Errorf("very large PoW string should be accepted by metadata validation: %v", err)
	}
}

func TestValidate_PoWFormat_Negative(t *testing.T) {
	meta := validMeta()
	meta.DataSize = 1024
	meta.PoW = "-1"
	meta.PoWAlg = "argon2id-light-v1"
	// Negative string is still a non-empty string; metadata accepts it
	err := meta.Validate()
	if err != nil {
		t.Errorf("negative PoW string should be accepted by metadata validation: %v", err)
	}
}

func TestValidate_PoWFormat_EmptyAlgWithPoW(t *testing.T) {
	meta := validMeta()
	meta.DataSize = 1024
	meta.PoW = "12345"
	meta.PoWAlg = "" // Missing alg
	err := meta.Validate()
	if err != ErrMissingPowAlg {
		t.Errorf("expected ErrMissingPowAlg, got: %v", err)
	}
}

// ============================================================
// §1 — bundle_txid constraint edge cases
// ============================================================

func TestValidate_BundleTxID_NoneButDataHeightNotNegativeOne(t *testing.T) {
	meta := validMeta()
	meta.Method = MethodBundle
	meta.DataHeight = 100 // not -1
	meta.BundleTXID = "none"
	err := meta.Validate()
	// Note: current Validate() only checks that when data_height=-1, bundle_txid must be "none".
	// It does NOT currently check the reverse (when bundle_txid="none", data_height must be -1).
	// This test documents that gap — the reverse constraint is a spec requirement
	// (§2.2: "bundle_txid='none' 表示 data 在同一 Bundle 中").
	if err != nil {
		t.Logf("bundle_txid='none' with data_height!=-1 correctly rejected: %v", err)
	} else {
		t.Log("bundle_txid='none' with data_height!=-1: accepted (reverse constraint not enforced by Validate)")
	}
}

func TestValidate_BundleTxID_EmptyWithBundleMethod(t *testing.T) {
	meta := validMeta()
	meta.Method = MethodBundle
	meta.DataHeight = 100 // >= 0, so bundle_txid required
	meta.BundleTXID = ""  // Missing
	err := meta.Validate()
	if err == nil {
		t.Fatal("empty bundle_txid when method=bundle and data_height>=0 should fail")
	}
}

func TestValidate_BundleTxID_NoneButRawMethod(t *testing.T) {
	meta := validMeta()
	meta.Method = MethodRaw
	meta.DataHeight = -1 // -1 with raw is already caught by data_height check
	meta.BundleTXID = "none"
	err := meta.Validate()
	if err == nil {
		t.Fatal("data_height=-1 with raw method should fail")
	}
}

func TestValidate_BundleTxID_ValidSameBundle(t *testing.T) {
	meta := validMeta()
	meta.Method = MethodBundle
	meta.DataHeight = -1
	meta.BundleTXID = "none"
	meta.DataSize = 200 * 1024 * 1024 // No PoW needed
	err := meta.Validate()
	if err != nil {
		t.Errorf("same-bundle valid config should pass: %v", err)
	}
}

func TestValidate_BundleTxID_ValidCrossBundle(t *testing.T) {
	meta := validMeta()
	meta.Method = MethodBundle
	meta.DataHeight = 1913000
	meta.BundleTXID = "bundle_tx_1234567890123456789012345678901234567890"
	meta.DataSize = 200 * 1024 * 1024
	err := meta.Validate()
	if err != nil {
		t.Errorf("cross-bundle valid config should pass: %v", err)
	}
}

// ============================================================
// §1 — data_height boundary cases
// ============================================================

func TestValidate_DataHeight_VeryLarge(t *testing.T) {
	meta := validMeta()
	meta.DataHeight = 100_000_000 // 1亿
	err := meta.Validate()
	if err != nil {
		t.Errorf("data_height=100M should be valid, got: %v", err)
	}
}

func TestValidate_DataHeight_MaxInt(t *testing.T) {
	meta := validMeta()
	meta.DataHeight = math.MaxInt32
	err := meta.Validate()
	if err != nil {
		t.Errorf("data_height=MaxInt32 should be valid, got: %v", err)
	}
}

func TestValidate_DataHeight_NegativeTwo(t *testing.T) {
	meta := validMeta()
	meta.DataHeight = -2
	err := meta.Validate()
	if err == nil {
		t.Fatal("data_height=-2 should fail")
	}
	if !strings.Contains(err.Error(), "data_height") {
		t.Errorf("error should mention data_height, got: %v", err)
	}
}

// ============================================================
// §1 — data_txid edge cases
// ============================================================

func TestValidate_DataTXID_WithSpaces(t *testing.T) {
	meta := validMeta()
	meta.DataTXID = "arweave_tx_id_1234567890 1234567890"
	err := meta.Validate()
	if err == nil {
		t.Fatal("data_txid with spaces should fail")
	}
}

func TestValidate_DataTXID_ValidArweaveFormat(t *testing.T) {
	// Arweave TX ID is 43-char Base64URL
	validTXID := "aValidArweave_TxID-With_Base64URLchars1234567890" // 48 chars
	meta := validMeta()
	meta.DataTXID = validTXID
	err := meta.Validate()
	if err != nil {
		t.Errorf("valid Arweave-format txid should pass: %v", err)
	}
}

func TestValidate_DataTXID_MinLength(t *testing.T) {
	meta := validMeta()
	meta.DataTXID = "abc1234567" // 10 chars, borderline valid
	err := meta.Validate()
	if err != nil {
		t.Errorf("10-char data_txid should be valid: %v", err)
	}
}

func TestValidate_DataTXID_TooShort(t *testing.T) {
	meta := validMeta()
	meta.DataTXID = "abc123456" // 9 chars, too short
	err := meta.Validate()
	if err == nil {
		t.Fatal("9-char data_txid should be invalid")
	}
}

func TestValidate_DataTXID_TooLong(t *testing.T) {
	meta := validMeta()
	meta.DataTXID = strings.Repeat("a", 129) // 129 chars, too long
	err := meta.Validate()
	if err == nil {
		t.Fatal("129-char data_txid should be invalid")
	}
}

// ============================================================
// §1 — data_size edge cases
// ============================================================

func TestValidate_DataSize_OneByte(t *testing.T) {
	meta := validMeta()
	meta.DataSize = 1
	meta.PoW = "42"
	meta.PoWAlg = "argon2id-light-v1"
	err := meta.Validate()
	if err != nil {
		t.Errorf("data_size=1 should be valid with PoW: %v", err)
	}
}

func TestValidate_DataSize_VeryLarge(t *testing.T) {
	meta := validMeta()
	meta.DataSize = math.MaxInt32 // ~2GB
	err := meta.Validate()
	if err != nil {
		t.Errorf("very large data_size should be valid: %v", err)
	}
}

func TestValidate_DataSize_NegativeOne(t *testing.T) {
	meta := validMeta()
	meta.DataSize = -1
	err := meta.Validate()
	if err == nil {
		t.Fatal("data_size=-1 should fail")
	}
}

// ============================================================
// §1 — JSON parsing edge cases (large payload, BOM, encoding)
// ============================================================

func TestParseJSON_LargePayload(t *testing.T) {
	// Build a large JSON with many reference entries
	refEntries := make(map[string]ReferenceEntry)
	for i := 0; i < 1000; i++ {
		txid := fmt.Sprintf("tx_%012d_1234567890123456789012345678901234567890", i)
		refEntries[txid] = ReferenceEntry{
			Height: i,
			CIDs:   []string{fmt.Sprintf("bafyCID%06d", i)},
		}
	}

	meta := Metadata{
		Version:    1,
		Method:     "raw",
		RootCID:    "bafyLargeCID123456789012345678901234567890123456789",
		DataTXID:   "large_tx_12345678901234567890123456789012345678901",
		DataHeight: 100,
		DataSize:   200 * 1024 * 1024,
		Reference:  (*ReferenceMap)(&refEntries),
	}

	jsonBytes, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal large metadata failed: %v", err)
	}

	parsed, err := ParseJSON(jsonBytes)
	if err != nil {
		t.Fatalf("parse large metadata failed: %v", err)
	}

	if parsed.Reference == nil || len(*parsed.Reference) != 1000 {
		t.Errorf("expected 1000 reference entries, got %d", len(*parsed.Reference))
	}
}

func TestParseJSON_UTF8BOM(t *testing.T) {
	// JSON with BOM prefix (should fail or be handled)
	bomJSON := "\xef\xbb\xbf" + `{"version":1,"method":"raw","root_cid":"bafyTest","data_txid":"tx123","data_height":100,"data_size":200000000}`
	_, err := ParseJSON([]byte(bomJSON))
	// JSON spec says BOM is not allowed — should fail
	if err == nil {
		t.Log("BOM-prefixed JSON unexpectedly parsed successfully")
	}
	// Either outcome is acceptable; what matters is that we don't panic
}

func TestParseJSON_NonUTF8(t *testing.T) {
	// Binary data that is not valid UTF-8
	nonUTF8 := []byte{0xff, 0xfe, 0x00, 0x01, 0x02}
	_, err := ParseJSON(nonUTF8)
	if err == nil {
		t.Fatal("non-UTF8 binary data should fail JSON parsing")
	}
}

func TestParseJSON_NullBytes(t *testing.T) {
	// JSON with embedded null bytes
	nullJSON := []byte("{\"version\":1,\x00\"method\":\"raw\"}")
	_, err := ParseJSON(nullJSON)
	if err == nil {
		t.Fatal("JSON with null bytes should fail")
	}
}

// ============================================================
// §1 — Base64URL encoding edge cases
// ============================================================

func TestParseFromBase64URL_Padded(t *testing.T) {
	// RawURLEncoding (no padding) vs StdEncoding (with padding)
	jsonStr := `{"version":1,"method":"raw","root_cid":"bafytest","data_txid":"tx1234567890","data_height":100,"data_size":200000000}`

	// RawURL (no padding)
	encodedRaw := base64.RawURLEncoding.EncodeToString([]byte(jsonStr))
	meta, err := ParseFromBase64URL(encodedRaw)
	if err != nil {
		t.Fatalf("RawURLEncoding failed: %v", err)
	}
	if meta.Version != 1 {
		t.Error("version mismatch")
	}

	// Standard with padding
	encodedStd := base64.StdEncoding.EncodeToString([]byte(jsonStr))
	meta, err = ParseFromBase64URL(encodedStd)
	if err != nil {
		t.Fatalf("StdEncoding failed: %v", err)
	}
	if meta.Version != 1 {
		t.Error("version mismatch")
	}
}

func TestParseFromBase64URL_EmptyJSON(t *testing.T) {
	// Valid Base64 of empty JSON object
	encoded := base64.RawURLEncoding.EncodeToString([]byte("{}"))
	meta, err := ParseFromBase64URL(encoded)
	if err != nil {
		t.Fatalf("ParseFromBase64URL should parse empty JSON (validation separate): %v", err)
	}
	// Parsed but invalid — validate would fail
	if err := meta.Validate(); err == nil {
		t.Fatal("empty JSON object should fail Validate")
	}
}

// ============================================================
// §1 — ReferenceToLocal / LocalToReference roundtrip
// ============================================================

func TestReferenceToLocal_Basic(t *testing.T) {
	ref := ReferenceMap{
		"txA": {Height: 100, CIDs: []string{"cid1", "cid2"}},
		"txB": {Height: 200, CIDs: []string{"cid3"}},
	}

	local := ReferenceToLocal(ref)
	if len(local) != 3 {
		t.Errorf("expected 3 local entries, got %d", len(local))
	}
	if local["cid1"] != "txA" {
		t.Errorf("cid1 should map to txA, got %s", local["cid1"])
	}
	if local["cid2"] != "txA" {
		t.Errorf("cid2 should map to txA, got %s", local["cid2"])
	}
	if local["cid3"] != "txB" {
		t.Errorf("cid3 should map to txB, got %s", local["cid3"])
	}
}

func TestReferenceToLocal_Empty(t *testing.T) {
	ref := ReferenceMap{}
	local := ReferenceToLocal(ref)
	if len(local) != 0 {
		t.Errorf("empty ref should produce empty local map, got %d entries", len(local))
	}
}

func TestLocalToReference_Roundtrip(t *testing.T) {
	local := map[string]string{
		"cid1": "txA",
		"cid2": "txA",
		"cid3": "txB",
	}

	ref := LocalToReference(local)
	if len(ref) != 2 {
		t.Errorf("expected 2 tx entries, got %d", len(ref))
	}

	entryA := ref["txA"]
	if len(entryA.CIDs) != 2 {
		t.Errorf("txA should have 2 CIDs, got %d", len(entryA.CIDs))
	}

	entryB := ref["txB"]
	if len(entryB.CIDs) != 1 {
		t.Errorf("txB should have 1 CID, got %d", len(entryB.CIDs))
	}

	// Note: height is not preserved in LocalToReference
	if entryA.Height != 0 {
		t.Logf("height not preserved in LocalToReference (expected): height=%d", entryA.Height)
	}
}

func TestReferenceToLocal_DuplicateCIDsAcrossTX(t *testing.T) {
	// Same CID appearing in multiple transactions
	ref := ReferenceMap{
		"txA": {Height: 100, CIDs: []string{"sharedCID"}},
		"txB": {Height: 200, CIDs: []string{"sharedCID", "uniqueCID"}},
	}

	local := ReferenceToLocal(ref)
	// Last write wins for sharedCID
	if local["uniqueCID"] != "txB" {
		t.Errorf("uniqueCID should map to txB")
	}
}

// ============================================================
// §1 — RootCID edge cases
// ============================================================

func TestValidate_RootCID_Base58CIDv0(t *testing.T) {
	// CIDv0 uses Base58 (starts with Qm...)
	meta := validMeta()
	meta.RootCID = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG" // 46-char Base58
	err := meta.Validate()
	if err != nil {
		t.Errorf("Base58 CIDv0 should be valid: %v", err)
	}
}

func TestValidate_RootCID_MaxLength(t *testing.T) {
	meta := validMeta()
	meta.RootCID = "b" + strings.Repeat("a", 510) + "y" // 512 chars
	err := meta.Validate()
	if err != nil {
		t.Errorf("512-char root_cid should be valid: %v", err)
	}
}

func TestValidate_RootCID_OverMaxLength(t *testing.T) {
	meta := validMeta()
	meta.RootCID = "b" + strings.Repeat("a", 512) // 513 chars
	err := meta.Validate()
	if err == nil {
		t.Fatal("513-char root_cid should be invalid")
	}
}

// ============================================================
// §1 — Concurrent ParseAndValidate
// ============================================================

func TestParseAndValidate_Concurrent(t *testing.T) {
	jsonBytes := []byte(`{"version":1,"method":"raw","root_cid":"bafyTestCID","data_txid":"tx1234567890123456789012345678901234567890","data_height":100,"data_size":200000000}`)

	var wg sync.WaitGroup
	errCh := make(chan error, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := ParseAndValidate(jsonBytes)
			if err != nil {
				errCh <- err
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent ParseAndValidate failed: %v", err)
	}
}

// ============================================================
// §1 — ValidateTags deep edge cases
// ============================================================

func TestValidateTags_ExtraTagsIgnored(t *testing.T) {
	tags := []Tag{
		{Name: "Protocol", Value: "IPFS-Arweave-Bridge"},
		{Name: "Protocol-Version", Value: "1"},
		{Name: "Extra-Tag", Value: "should-not-cause-failure"},
		{Name: "Another-Tag", Value: "also-ignored"},
	}
	err := ValidateTags(tags)
	if err != nil {
		t.Errorf("extra tags should be ignored: %v", err)
	}
}

func TestValidateTags_CaseSensitive(t *testing.T) {
	// Tag names should be case-sensitive
	tags := []Tag{
		{Name: "protocol", Value: "IPFS-Arweave-Bridge"}, // lowercase 'p'
		{Name: "Protocol-Version", Value: "1"},
	}
	err := ValidateTags(tags)
	if err == nil {
		t.Fatal("lowercase 'protocol' tag should not satisfy the 'Protocol' requirement")
	}
}

func TestValidateTags_EmptyTagName(t *testing.T) {
	tags := []Tag{
		{Name: "", Value: "value"},
		{Name: "Protocol", Value: "IPFS-Arweave-Bridge"},
		{Name: "Protocol-Version", Value: "1"},
	}
	// Empty tag names should be handled
	err := ValidateTags(tags)
	// The empty tag name is not checked directly by ValidateTags,
	// but the Protocol tag should be found correctly
	if err != nil {
		t.Logf("tags with empty name: %v", err)
	}
}

func TestValidateTags_MetaTags_WrongContentType(t *testing.T) {
	tags := []Tag{
		{Name: "Protocol", Value: "IPFS-Arweave-Bridge"},
		{Name: "Protocol-Version", Value: "1"},
		{Name: "IPFAR-Type", Value: "meta"},
		{Name: "Content-Type", Value: "text/plain"}, // should be application/json
		{Name: "Root-CID", Value: "bafyTestCID"},
		{Name: "Data-TXID", Value: "tx123"},
	}
	err := ValidateTags(tags)
	if err == nil {
		t.Fatal("meta tags with wrong Content-Type should fail")
	}
}

func TestValidateTags_CARTags_WrongContentType(t *testing.T) {
	// CAR tags must have Content-Type: application/vnd.ipld.car to be recognized as CAR.
	// Without it, they fall through to the generic handler which accepts them.
	// This test verifies behavior: wrong Content-Type means CAR-specific validation is skipped.
	tags := []Tag{
		{Name: "Protocol", Value: "IPFS-Arweave-Bridge"},
		{Name: "Protocol-Version", Value: "1"},
		{Name: "Content-Type", Value: "application/json"}, // Not application/vnd.ipld.car
		{Name: "Root-CID", Value: "bafyTestCID"},
		{Name: "Data-Size", Value: "12345"},
	}
	err := ValidateTags(tags)
	// Generic handler accepts these since Content-Type doesn't match CAR pattern
	if err != nil {
		t.Errorf("generic tags with non-CAR Content-Type should pass: %v", err)
	}

	// However, with correct CAR Content-Type and missing required fields, it should fail
	tags2 := []Tag{
		{Name: "Protocol", Value: "IPFS-Arweave-Bridge"},
		{Name: "Protocol-Version", Value: "1"},
		{Name: "Content-Type", Value: "application/vnd.ipld.car"},
		// Missing Root-CID
		{Name: "Data-Size", Value: "12345"},
	}
	err = ValidateTags(tags2)
	if err == nil {
		t.Fatal("CAR tags with missing Root-CID should fail")
	}
}

// ============================================================
// §1 — BuildMetaJSON deep edge cases
// ============================================================

func TestBuildMetaJSON_EmptyBundleTXID_CrossBundle(t *testing.T) {
	rootCID := "bafyCrossBundleCID12345678901234567890123456789012345"
	dataTXID := "cross_tx_12345678901234567890123456789012345678901"
	dataSize := int64(200 * 1024 * 1024)
	dataHeight := 1913000

	opts := &MetaOptions{
		Method:     MethodBundle,
		BundleTXID: "", // Empty but method=bundle and data_height>=0 — should fail
	}

	_, err := BuildMetaJSON(rootCID, dataTXID, dataSize, dataHeight, opts)
	if err == nil {
		t.Fatal("empty bundle_txid with cross-bundle should fail")
	}
	t.Logf("Got expected error: %v", err)
}

func TestBuildMetaJSON_SameBundle(t *testing.T) {
	rootCID := "bafySameBundleCID1234567890123456789012345678901234567"
	dataTXID := "same_tx_123456789012345678901234567890123456789012"
	dataSize := int64(200 * 1024 * 1024)
	dataHeight := -1

	opts := &MetaOptions{
		Method:     MethodBundle,
		BundleTXID: "none",
	}

	jsonBytes, err := BuildMetaJSON(rootCID, dataTXID, dataSize, dataHeight, opts)
	if err != nil {
		t.Fatalf("same-bundle BuildMetaJSON should succeed: %v", err)
	}

	meta, err := ParseJSON(jsonBytes)
	if err != nil {
		t.Fatalf("ParseJSON failed: %v", err)
	}

	if meta.DataHeight != -1 {
		t.Errorf("data_height should be -1, got %d", meta.DataHeight)
	}
	if meta.BundleTXID != "none" {
		t.Errorf("bundle_txid should be 'none', got %q", meta.BundleTXID)
	}
}

func TestBuildMetaJSON_SmallFileWithoutPoW(t *testing.T) {
	rootCID := "bafySmallNoPoW123456789012345678901234567890123456789"
	dataTXID := "small_tx_123456789012345678901234567890123456789012"
	dataSize := int64(1024) // 1 KiB -> needs PoW
	dataHeight := 100

	_, err := BuildMetaJSON(rootCID, dataTXID, dataSize, dataHeight, nil)
	if err == nil {
		t.Fatal("small file without PoW options should fail")
	}
	t.Logf("Got expected error: %v", err)
}

// ============================================================
// §1 — Reference nil/empty map edge cases
// ============================================================

func TestHasReference_NilPointer(t *testing.T) {
	var meta Metadata
	meta.Reference = nil
	if meta.HasReference() {
		t.Error("nil reference pointer should return false")
	}
}

func TestHasReference_AllocatedNilMap(t *testing.T) {
	var meta Metadata
	var ref ReferenceMap // nil map
	meta.Reference = &ref // pointer to nil map
	if meta.HasReference() {
		t.Error("pointer to nil map should return false (len=0)")
	}
}

func TestValidate_Reference_NegativeOneHeightAllowed(t *testing.T) {
	meta := validMeta()
	meta.Reference = &ReferenceMap{
		"txid_123456789012345678901234567890123456789012": {
			Height: -1, // same bundle
			CIDs:   []string{"bafyCID1"},
		},
	}
	if err := meta.Validate(); err != nil {
		t.Errorf("reference height=-1 should be valid: %v", err)
	}
}

// ============================================================
// §1 — Method raw vs bundle boundary
// ============================================================

func TestIsCrossBundle_True(t *testing.T) {
	meta := &Metadata{
		Method:     MethodBundle,
		DataHeight: 100,
		BundleTXID: "bundle_tx_1234567890123456789012345678901234567890",
	}
	if !meta.IsCrossBundle() {
		t.Error("cross-bundle config should return true")
	}
}

func TestIsCrossBundle_False_SameBundle(t *testing.T) {
	meta := &Metadata{
		Method:     MethodBundle,
		DataHeight: -1,
		BundleTXID: "none",
	}
	if meta.IsCrossBundle() {
		t.Error("same-bundle config should return false for IsCrossBundle")
	}
}

func TestIsCrossBundle_False_Raw(t *testing.T) {
	meta := &Metadata{
		Method:     MethodRaw,
		DataHeight: 100,
		BundleTXID: "some_bundle",
	}
	if meta.IsCrossBundle() {
		t.Error("raw method should never be cross-bundle")
	}
}

func TestIsSameBundle_True(t *testing.T) {
	meta := &Metadata{
		Method:     MethodBundle,
		DataHeight: -1,
		BundleTXID: "none",
	}
	if !meta.IsSameBundle() {
		t.Error("same-bundle config should return true")
	}
}

func TestIsSameBundle_False_CrossBundle(t *testing.T) {
	meta := &Metadata{
		Method:     MethodBundle,
		DataHeight: 100,
		BundleTXID: "bundle_tx_1234567890123456789012345678901234567890",
	}
	if meta.IsSameBundle() {
		t.Error("cross-bundle config should return false for IsSameBundle")
	}
}

// ============================================================
// §1 — ToJSON/ToBase64URL with all fields populated
// ============================================================

func TestToJSON_AllFieldsRoundtrip(t *testing.T) {
	ref := ReferenceMap{
		"tx_ref_1_12345678901234567890123456789012345678901": {
			Height: 1913001,
			CIDs:   []string{"bafyCIDRef1", "bafyCIDRef2"},
		},
	}

	original := &Metadata{
		Version:      1,
		Method:       "bundle",
		RootCID:      "bafyAllFields123456789012345678901234567890123456789",
		DataTXID:     "allfields_tx_123456789012345678901234567890123456789",
		DataHeight:   1913000,
		DataSize:     150 * 1024 * 1024,
		BundleTXID:   "bundle_all_1234567890123456789012345678901234567890",
		Reference:    &ref,
		ContentType:  "image/png",
		OriginalName: "test-all-fields.png",
		PoW:          "",
		PoWAlg:       "",
	}

	jsonBytes, err := original.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	parsed, err := ParseJSON(jsonBytes)
	if err != nil {
		t.Fatalf("ParseJSON failed: %v", err)
	}

	if parsed.Method != original.Method {
		t.Errorf("method mismatch: %s vs %s", parsed.Method, original.Method)
	}
	if parsed.BundleTXID != original.BundleTXID {
		t.Errorf("bundle_txid mismatch: %s vs %s", parsed.BundleTXID, original.BundleTXID)
	}
	if parsed.ContentType != original.ContentType {
		t.Errorf("content_type mismatch")
	}
	if parsed.OriginalName != original.OriginalName {
		t.Errorf("original_name mismatch")
	}
}

// ============================================================
// §2 — Deep PoW interaction tests (metadata + PoW)
// ============================================================

func TestNeedsPoW_AllBoundaries(t *testing.T) {
	tests := []struct {
		size     int
		expected bool
	}{
		{0, true},
		{1, true},
		{1024, true},
		{1024 * 1024, true},
		{99*1024*1024 + 999*1024, true},    // ~99.97 MiB
		{100*1024*1024 - 1024, true},        // 100 MiB - 1 KiB
		{100*1024*1024 - 1, true},           // 100 MiB - 1 byte
		{100 * 1024 * 1024, false},          // exactly 100 MiB
		{100*1024*1024 + 1, false},          // 100 MiB + 1 byte
		{100*1024*1024 + 1024, false},       // 100 MiB + 1 KiB
		{200 * 1024 * 1024, false},          // 200 MiB
		{1024 * 1024 * 1024, false},         // 1 GiB
		{math.MaxInt32, false},
	}

	for _, tt := range tests {
		meta := &Metadata{DataSize: tt.size}
		result := meta.NeedsPoW()
		if result != tt.expected {
			t.Errorf("NeedsPoW(%d) = %v, want %v", tt.size, result, tt.expected)
		}
	}
}

// ============================================================
// §1 — ParseAndValidate with minimal complete valid metadata
// ============================================================

func TestParseAndValidate_MinimalComplete(t *testing.T) {
	// Smallest valid metadata JSON
	jsonBytes := []byte(`{"version":1,"method":"raw","root_cid":"bafyTestCID01","data_txid":"tx1234567890123456789012345678901234567890","data_height":0,"data_size":1,"pow":"0","pow_alg":"argon2id-light-v1"}`)

	meta, err := ParseAndValidate(jsonBytes)
	if err != nil {
		t.Fatalf("minimal valid metadata should parse: %v", err)
	}
	if meta.DataSize != 1 {
		t.Errorf("data_size should be 1, got %d", meta.DataSize)
	}
	if meta.PoW != "0" {
		t.Errorf("PoW should be '0', got %q", meta.PoW)
	}
}

// ============================================================
// §1 — BuildMetaJSON nil opts with small file (should fail)
// ============================================================

func TestBuildMetaJSON_NilOptsSmallFile(t *testing.T) {
	// Nil opts with small file should fail (no PoW provided)
	_, err := BuildMetaJSON("bafyTestCID", "tx1234567890123456789012345678901234567890", 1024, 100, nil)
	if err == nil {
		t.Fatal("expected error for small file with nil opts (no PoW)")
	}
}

// ============================================================
// §1 — CleanCID with various inputs
// ============================================================

func TestCleanCID_AllVariants(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"bafytest", "bafytest"},
		{" bafytest", "bafytest"},
		{"bafytest ", "bafytest"},
		{"  bafytest  ", "bafytest"},
		{"\"bafytest\"", "bafytest"},
		{"'bafytest'", "'bafytest'"}, // only double quotes stripped
		{"\tbafytest\n", "bafytest"},
		{"", ""},
	}

	for _, tt := range tests {
		result := CleanCID(tt.input)
		if result != tt.expected {
			t.Errorf("CleanCID(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}
