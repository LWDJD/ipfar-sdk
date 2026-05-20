package main

import (
	"encoding/json"
	"fmt"
	"os"

	sdkmeta "github.com/LWDJD/ipfar-sdk/verify/metadata"
)

type testCase struct {
	id   int
	name string
	fn   func() error
}

var tests []testCase

func register(id int, name string, fn func() error) {
	tests = append(tests, testCase{id, name, fn})
}

func report(name string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "  FAIL: %s - %v\n", name, err)
	} else {
		fmt.Fprintf(os.Stderr, "  PASS: %s\n", name)
	}
}

func main() {
	register(1, "Upload PoW integration", testUploadPoW)
	register(2, "data_height = -1 allowed", testDataHeightNegativeOne)
	register(3, "reference height = -1 allowed", testRefHeightNegativeOne)
	register(4, "BundleTXID field in ReferenceEntry", testBundleTXIDField)
	register(5, "Bundle mode packaging", testBundleMode)
	register(6, "Reference chain resolution", testRefChain)

	if len(os.Args) > 1 && os.Args[1] == "list" {
		for _, t := range tests {
			fmt.Printf("  %d: %s\n", t.id, t.name)
		}
		return
	}

	passed := 0
	failed := 0
	for _, t := range tests {
		fmt.Fprintf(os.Stderr, "=== Test %d: %s ===\n", t.id, t.name)
		err := t.fn()
		report(t.name, err)
		if err != nil {
			failed++
		} else {
			passed++
		}
	}
	fmt.Fprintf(os.Stderr, "========================================\n")
	fmt.Fprintf(os.Stderr, "Results: %d passed, %d failed\n", passed, failed)
	if failed > 0 {
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "ALL TESTS PASSED\n")
}

// Test 1: Upload PoW integration
func testUploadPoW() error {
	meta, err := sdkmeta.BuildMetaJSON("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
		"test-txid-abc", 1024, 100, &sdkmeta.MetaOptions{
		Method: "raw", PoW: "12345678", PoWAlg: "argon2id-light-v1",
	})
	if err != nil {
		return fmt.Errorf("BuildMetaJSON with PoW should pass: %w", err)
	}
	parsed, err := sdkmeta.ParseJSON(meta)
	if err != nil {
		return fmt.Errorf("ParseJSON: %w", err)
	}
	if parsed.PoW != "12345678" {
		return fmt.Errorf("expected PoW=12345678, got %q", parsed.PoW)
	}
	if parsed.PoWAlg != "argon2id-light-v1" {
		return fmt.Errorf("expected PoWAlg=argon2id-light-v1, got %q", parsed.PoWAlg)
	}
	return nil
}

// Test 2: data_height = -1 allowed
func testDataHeightNegativeOne() error {
	meta := &sdkmeta.Metadata{
		Version: 1, Method: "bundle",
		RootCID: "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
		DataTXID: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", DataHeight: -1, DataSize: 1024,
		BundleTXID: "none", PoW: "1234", PoWAlg: "argon2id-light-v1",
	}
	err := meta.Validate()
	if err != nil {
		return fmt.Errorf("data_height=-1 should be valid: %w", err)
	}
	return nil
}

// Test 3: reference height = -1 allowed
func testRefHeightNegativeOne() error {
	ref := sdkmeta.ReferenceMap{
		"ref-txid": {Height: -1, CIDs: []string{"bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"}},
	}
	meta := &sdkmeta.Metadata{
		Version: 1, Method: "raw",
		RootCID: "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
		DataTXID: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", DataHeight: 100, DataSize: 1024,
		Reference: &ref, PoW: "1234", PoWAlg: "argon2id-light-v1",
	}
	err := meta.Validate()
	if err != nil {
		return fmt.Errorf("reference height=-1 should be valid: %w", err)
	}
	return nil
}

// Test 4: BundleTXID field in ReferenceEntry
func testBundleTXIDField() error {
	ref := sdkmeta.ReferenceMap{
		"ref-txid": {Height: 100, CIDs: []string{"cid1"}, BundleTXID: "parent-bundle-tx"},
	}
	meta := &sdkmeta.Metadata{
		Version: 1, Method: "raw",
		RootCID: "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
		DataTXID: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", DataHeight: 100, DataSize: 1024,
		Reference: &ref, PoW: "1234", PoWAlg: "argon2id-light-v1",
	}
	err := meta.Validate()
	if err != nil {
		return fmt.Errorf("reference with BundleTXID should be valid: %w", err)
	}
	jsonData, _ := json.Marshal(meta)
	var parsed map[string]interface{}
	json.Unmarshal(jsonData, &parsed)
	refMap, ok := parsed["reference"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("reference not found in JSON")
	}
	entry, ok := refMap["ref-txid"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("ref-txid not found in reference JSON")
	}
	btxid, ok := entry["bundle_txid"]
	if !ok || btxid != "parent-bundle-tx" {
		return fmt.Errorf("bundle_txid field missing or wrong in JSON output")
	}
	return nil
}

// Test 5: Bundle mode packaging
func testBundleMode() error {
	meta, err := sdkmeta.BuildMetaJSON("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
		"bundle-txid-test", 1048576, 2000000, &sdkmeta.MetaOptions{
		Method: "bundle", BundleTXID: "none",
		ContentType: "application/octet-stream",
		OriginalName: "test.bin",
		PoW: "1234", PoWAlg: "argon2id-light-v1",
	})
	if err != nil {
		return fmt.Errorf("BuildMetaJSON with bundle method: %w", err)
	}
	parsed, err := sdkmeta.ParseJSON(meta)
	if err != nil {
		return fmt.Errorf("ParseJSON: %w", err)
	}
	if parsed.Method != "bundle" {
		return fmt.Errorf("expected method=bundle, got %q", parsed.Method)
	}
	if parsed.BundleTXID != "none" {
		return fmt.Errorf("expected BundleTXID=none, got %q", parsed.BundleTXID)
	}
	return nil
}

// Test 6: Reference chain resolution
func testRefChain() error {
	ref := sdkmeta.ReferenceMap{
		"txid-1": {Height: 100, CIDs: []string{"cid-a", "cid-b"}},
		"txid-2": {Height: 200, CIDs: []string{"cid-c"}, BundleTXID: "parent-bundle"},
	}
	meta := &sdkmeta.Metadata{
		Version: 1, Method: "raw",
		RootCID: "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
		DataTXID: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", DataHeight: 300, DataSize: 2048,
		Reference: &ref, PoW: "1234", PoWAlg: "argon2id-light-v1",
	}
	err := meta.Validate()
	if err != nil {
		return fmt.Errorf("reference chain validation: %w", err)
	}
	if !meta.HasReference() {
		return fmt.Errorf("HasReference should be true")
	}
	jsonData, _ := json.Marshal(meta)
	parsed, err := sdkmeta.ParseJSON(jsonData)
	if err != nil {
		return fmt.Errorf("roundtrip ParseJSON: %w", err)
	}
	if parsed.Reference == nil || len(*parsed.Reference) != 2 {
		return fmt.Errorf("expected 2 references, got %d", len(*parsed.Reference))
	}
	entry1 := (*parsed.Reference)["txid-1"]
	if entry1.Height != 100 || len(entry1.CIDs) != 2 {
		return fmt.Errorf("txid-1 reference mismatch")
	}
	entry2 := (*parsed.Reference)["txid-2"]
	if entry2.BundleTXID != "parent-bundle" {
		return fmt.Errorf("txid-2 bundle_txid mismatch")
	}
	return nil
}
