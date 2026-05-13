package metadata

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// ============================================================
// ParseJSON 测试
// ============================================================

func TestParseJSON_Valid(t *testing.T) {
	jsonStr := `{
		"version": 1,
		"method": "raw",
		"root_cid": "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
		"data_txid": "arweave_tx_id_1234567890123456789012345678901234567890",
		"data_height": 1913000,
		"data_size": 12345678,
		"content_type": "image/png",
		"original_name": "myfile.png",
		"pow": "12345",
		"pow_alg": "argon2id-light-v1"
	}`

	meta, err := ParseJSON([]byte(jsonStr))
	if err != nil {
		t.Fatalf("ParseJSON failed: %v", err)
	}

	if meta.Version != 1 {
		t.Errorf("Version = %d, want 1", meta.Version)
	}
	if meta.Method != "raw" {
		t.Errorf("Method = %s, want raw", meta.Method)
	}
	if meta.RootCID != "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi" {
		t.Errorf("RootCID mismatch")
	}
	if meta.DataTXID != "arweave_tx_id_1234567890123456789012345678901234567890" {
		t.Errorf("DataTXID mismatch")
	}
	if meta.DataHeight != 1913000 {
		t.Errorf("DataHeight = %d, want 1913000", meta.DataHeight)
	}
	if meta.DataSize != 12345678 {
		t.Errorf("DataSize = %d, want 12345678", meta.DataSize)
	}
	if meta.ContentType != "image/png" {
		t.Errorf("ContentType = %s, want image/png", meta.ContentType)
	}
	if meta.OriginalName != "myfile.png" {
		t.Errorf("OriginalName = %s, want myfile.png", meta.OriginalName)
	}
	if meta.PoW != "12345" {
		t.Errorf("PoW = %s, want 12345", meta.PoW)
	}
	if meta.PoWAlg != "argon2id-light-v1" {
		t.Errorf("PoWAlg = %s, want argon2id-light-v1", meta.PoWAlg)
	}
}

func TestParseJSON_Minimal(t *testing.T) {
	jsonStr := `{
		"version": 1,
		"method": "raw",
		"root_cid": "bafytest",
		"data_txid": "tx123",
		"data_height": 100,
		"data_size": 200000000,
		"pow": "",
		"pow_alg": ""
	}`

	meta, err := ParseJSON([]byte(jsonStr))
	if err != nil {
		t.Fatalf("ParseJSON minimal failed: %v", err)
	}

	if meta.Version != 1 {
		t.Errorf("Version = %d, want 1", meta.Version)
	}
	// Large file (200MB) doesn't need PoW
	if meta.NeedsPoW() {
		t.Error("Large file should not need PoW")
	}
}

func TestParseJSON_Empty(t *testing.T) {
	_, err := ParseJSON([]byte{})
	if err == nil {
		t.Fatal("Expected error for empty JSON")
	}
}

func TestParseJSON_InvalidJSON(t *testing.T) {
	_, err := ParseJSON([]byte("{invalid json"))
	if err == nil {
		t.Fatal("Expected error for invalid JSON")
	}
}

func TestParseJSON_WithReference(t *testing.T) {
	jsonStr := `{
		"version": 1,
		"method": "bundle",
		"root_cid": "bafyTestCID",
		"data_txid": "main_tx_id_1234567890123456789012345678901234567890",
		"data_height": 1913000,
		"data_size": 5000000,
		"reference": {
			"chunk_tx_1_12345678901234567890123456789012345678901": {
				"height": 1913001,
				"cids": ["bafySharedCID1", "bafySharedCID2"]
			},
			"chunk_tx_2_12345678901234567890123456789012345678902": {
				"height": 1913002,
				"cids": ["bafySharedCID3"]
			}
		},
		"pow": "42",
		"pow_alg": "argon2id-light-v1"
	}`

	meta, err := ParseJSON([]byte(jsonStr))
	if err != nil {
		t.Fatalf("ParseJSON with reference failed: %v", err)
	}

	if !meta.HasReference() {
		t.Fatal("Expected HasReference to be true")
	}

	if meta.Reference == nil {
		t.Fatal("Reference should not be nil")
	}

	if len(*meta.Reference) != 2 {
		t.Errorf("Reference count = %d, want 2", len(*meta.Reference))
	}
}

// ============================================================
// ParseFromBase64URL 测试
// ============================================================

func TestParseFromBase64URL_Valid(t *testing.T) {
	jsonStr := `{"version":1,"method":"raw","root_cid":"bafytest","data_txid":"tx123","data_height":100,"data_size":200000000}`
	encoded := base64.RawURLEncoding.EncodeToString([]byte(jsonStr))

	meta, err := ParseFromBase64URL(encoded)
	if err != nil {
		t.Fatalf("ParseFromBase64URL failed: %v", err)
	}

	if meta.Version != 1 {
		t.Errorf("Version = %d, want 1", meta.Version)
	}
}

func TestParseFromBase64URL_Empty(t *testing.T) {
	_, err := ParseFromBase64URL("")
	if err == nil {
		t.Fatal("Expected error for empty Base64URL")
	}
}

func TestParseFromBase64URL_InvalidBase64(t *testing.T) {
	_, err := ParseFromBase64URL("!!!not-valid-base64!!!")
	if err == nil {
		t.Fatal("Expected error for invalid Base64")
	}
}

func TestParseFromBase64URL_StandardBase64(t *testing.T) {
	// 测试标准 Base64（带填充）也能解码
	jsonStr := `{"version":1,"method":"raw","root_cid":"bafytest","data_txid":"tx123","data_height":100,"data_size":200000000}`
	encoded := base64.StdEncoding.EncodeToString([]byte(jsonStr))

	meta, err := ParseFromBase64URL(encoded)
	if err != nil {
		t.Fatalf("ParseFromBase64URL with standard Base64 failed: %v", err)
	}

	if meta.Version != 1 {
		t.Errorf("Version = %d, want 1", meta.Version)
	}
}

// ============================================================
// Validate 测试 — 必填字段
// ============================================================

func TestValidate_Valid(t *testing.T) {
	meta := validMeta()
	if err := meta.Validate(); err != nil {
		t.Errorf("Valid metadata should pass validation, got: %v", err)
	}
}

func TestValidate_MissingVersion(t *testing.T) {
	meta := validMeta()
	meta.Version = 0
	err := meta.Validate()
	if err == nil {
		t.Fatal("Expected error for missing version")
	}
}

func TestValidate_InvalidVersion(t *testing.T) {
	meta := validMeta()
	meta.Version = 99
	err := meta.Validate()
	if err == nil {
		t.Fatal("Expected error for invalid version")
	}
}

func TestValidate_MissingMethod(t *testing.T) {
	meta := validMeta()
	meta.Method = ""
	err := meta.Validate()
	if err == nil {
		t.Fatal("Expected error for missing method")
	}
}

func TestValidate_InvalidMethod(t *testing.T) {
	meta := validMeta()
	meta.Method = "invalid_method"
	err := meta.Validate()
	if err == nil {
		t.Fatal("Expected error for invalid method")
	}
}

func TestValidate_MethodBundle(t *testing.T) {
	meta := validMeta()
	meta.Method = "bundle"
	if err := meta.Validate(); err != nil {
		t.Errorf("Method 'bundle' should be valid, got: %v", err)
	}
}

func TestValidate_MissingRootCID(t *testing.T) {
	meta := validMeta()
	meta.RootCID = ""
	err := meta.Validate()
	if err == nil {
		t.Fatal("Expected error for missing root_cid")
	}
}

func TestValidate_InvalidRootCID(t *testing.T) {
	tests := []string{
		"",
		"!!!invalid!!!",
		"a", // too short
	}
	for _, cid := range tests {
		meta := validMeta()
		meta.RootCID = cid
		err := meta.Validate()
		if err == nil {
			t.Errorf("Expected error for invalid root_cid %q", cid)
		}
	}
}

func TestValidate_MissingDataTXID(t *testing.T) {
	meta := validMeta()
	meta.DataTXID = ""
	err := meta.Validate()
	if err == nil {
		t.Fatal("Expected error for missing data_txid")
	}
}

func TestValidate_InvalidDataTXID(t *testing.T) {
	tests := []string{
		"",
		"!!!invalid!!!",
		"a", // too short
	}
	for _, txid := range tests {
		meta := validMeta()
		meta.DataTXID = txid
		err := meta.Validate()
		if err == nil {
			t.Errorf("Expected error for invalid data_txid %q", txid)
		}
	}
}

func TestValidate_NegativeDataHeight(t *testing.T) {
	meta := validMeta()
	meta.DataHeight = -1
	err := meta.Validate()
	if err == nil {
		t.Fatal("Expected error for negative data_height")
	}
}

func TestValidate_ZeroDataHeight(t *testing.T) {
	meta := validMeta()
	meta.DataHeight = 0
	// Height 0 是合法的（创世区块）
	if err := meta.Validate(); err != nil {
		t.Errorf("Zero data_height should be valid, got: %v", err)
	}
}

func TestValidate_ZeroDataSize(t *testing.T) {
	meta := validMeta()
	meta.DataSize = 0
	err := meta.Validate()
	if err == nil {
		t.Fatal("Expected error for zero data_size")
	}
}

func TestValidate_NegativeDataSize(t *testing.T) {
	meta := validMeta()
	meta.DataSize = -100
	err := meta.Validate()
	if err == nil {
		t.Fatal("Expected error for negative data_size")
	}
}

// ============================================================
// Validate 测试 — 条件必填字段（PoW）
// ============================================================

func TestValidate_SmallFileMissingPoW(t *testing.T) {
	meta := validMeta()
	meta.DataSize = 1024 // 1 KiB，需要 PoW
	meta.PoW = ""
	meta.PoWAlg = ""
	err := meta.Validate()
	if err == nil {
		t.Fatal("Expected error for missing PoW on small file")
	}
	if err != ErrMissingPoW {
		t.Errorf("Expected ErrMissingPoW, got: %v", err)
	}
}

func TestValidate_SmallFileMissingPoWAlg(t *testing.T) {
	meta := validMeta()
	meta.DataSize = 1024
	meta.PoW = "12345"
	meta.PoWAlg = ""
	err := meta.Validate()
	if err == nil {
		t.Fatal("Expected error for missing PoWAlg on small file")
	}
	if err != ErrMissingPowAlg {
		t.Errorf("Expected ErrMissingPowAlg, got: %v", err)
	}
}

func TestValidate_LargeFileMissingPoW(t *testing.T) {
	meta := validMeta()
	meta.DataSize = 200 * 1024 * 1024 // 200 MiB，不需要 PoW
	meta.PoW = ""
	meta.PoWAlg = ""
	if err := meta.Validate(); err != nil {
		t.Errorf("Large file without PoW should be valid, got: %v", err)
	}
}

func TestValidate_ExactlyAtThreshold(t *testing.T) {
	meta := validMeta()
	meta.DataSize = 100 * 1024 * 1024 // 正好 100 MiB
	meta.PoW = ""
	meta.PoWAlg = ""
	if err := meta.Validate(); err != nil {
		t.Errorf("File at threshold should be valid without PoW, got: %v", err)
	}
}

func TestValidate_JustBelowThreshold(t *testing.T) {
	meta := validMeta()
	meta.DataSize = (100 * 1024 * 1024) - 1 // 100 MiB - 1 byte
	meta.PoW = ""
	meta.PoWAlg = ""
	err := meta.Validate()
	if err == nil {
		t.Fatal("File just below threshold should require PoW")
	}
}

// ============================================================
// Validate 测试 — Reference 验证
// ============================================================

func TestValidate_ValidReference(t *testing.T) {
	meta := validMeta()
	meta.Reference = &ReferenceMap{
		"txid_123456789012345678901234567890123456789012": {
			Height: 1913001,
			CIDs:   []string{"bafyCID1"},
		},
	}
	if err := meta.Validate(); err != nil {
		t.Errorf("Valid reference should pass, got: %v", err)
	}
}

func TestValidate_ReferenceEmptyTXID(t *testing.T) {
	meta := validMeta()
	meta.Reference = &ReferenceMap{
		"": {
			Height: 100,
			CIDs:   []string{"bafyCID1"},
		},
	}
	err := meta.Validate()
	if err == nil {
		t.Fatal("Expected error for reference with empty txid")
	}
}

func TestValidate_ReferenceNegativeHeight(t *testing.T) {
	meta := validMeta()
	meta.Reference = &ReferenceMap{
		"txid_123456789012345678901234567890123456789012": {
			Height: -1,
			CIDs:   []string{"bafyCID1"},
		},
	}
	err := meta.Validate()
	if err == nil {
		t.Fatal("Expected error for reference with negative height")
	}
}

func TestValidate_ReferenceEmptyCIDs(t *testing.T) {
	meta := validMeta()
	meta.Reference = &ReferenceMap{
		"txid_123456789012345678901234567890123456789012": {
			Height: 100,
			CIDs:   []string{},
		},
	}
	err := meta.Validate()
	if err == nil {
		t.Fatal("Expected error for reference with empty CIDs")
	}
}

func TestValidate_ReferenceEmptyCIDString(t *testing.T) {
	meta := validMeta()
	meta.Reference = &ReferenceMap{
		"txid_123456789012345678901234567890123456789012": {
			Height: 100,
			CIDs:   []string{""},
		},
	}
	err := meta.Validate()
	if err == nil {
		t.Fatal("Expected error for reference with empty CID string")
	}
}

func TestValidate_NilReference(t *testing.T) {
	meta := validMeta()
	meta.Reference = nil
	if err := meta.Validate(); err != nil {
		t.Errorf("Nil reference should be valid, got: %v", err)
	}
}

func TestValidate_EmptyReference(t *testing.T) {
	meta := validMeta()
	emptyRef := ReferenceMap{}
	meta.Reference = &emptyRef
	if err := meta.Validate(); err != nil {
		t.Errorf("Empty reference map should be valid, got: %v", err)
	}
}

// ============================================================
// NeedsPoW / HasReference 测试
// ============================================================

func TestNeedsPoW(t *testing.T) {
	tests := []struct {
		size     int
		expected bool
	}{
		{0, true},
		{1024, true},
		{100*1024*1024 - 1, true},
		{100 * 1024 * 1024, false},
		{200 * 1024 * 1024, false},
	}

	for _, tt := range tests {
		meta := &Metadata{DataSize: tt.size}
		if result := meta.NeedsPoW(); result != tt.expected {
			t.Errorf("NeedsPoW(%d) = %v, want %v", tt.size, result, tt.expected)
		}
	}
}

func TestHasReference(t *testing.T) {
	meta := &Metadata{}
	if meta.HasReference() {
		t.Error("Nil reference should return false")
	}

	emptyRef := ReferenceMap{}
	meta.Reference = &emptyRef
	if meta.HasReference() {
		t.Error("Empty reference should return false")
	}

	ref := ReferenceMap{"tx": {Height: 1, CIDs: []string{"cid"}}}
	meta.Reference = &ref
	if !meta.HasReference() {
		t.Error("Non-empty reference should return true")
	}
}

// ============================================================
// ToJSON / ToBase64URL 测试
// ============================================================

func TestToJSON_Roundtrip(t *testing.T) {
	original := validMeta()
	jsonBytes, err := original.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	parsed, err := ParseJSON(jsonBytes)
	if err != nil {
		t.Fatalf("ParseJSON failed: %v", err)
	}

	if parsed.Version != original.Version {
		t.Error("Roundtrip version mismatch")
	}
	if parsed.RootCID != original.RootCID {
		t.Error("Roundtrip root_cid mismatch")
	}
}

func TestToBase64URL_Roundtrip(t *testing.T) {
	original := validMeta()
	encoded, err := original.ToBase64URL()
	if err != nil {
		t.Fatalf("ToBase64URL failed: %v", err)
	}

	parsed, err := ParseFromBase64URL(encoded)
	if err != nil {
		t.Fatalf("ParseFromBase64URL failed: %v", err)
	}

	if parsed.RootCID != original.RootCID {
		t.Error("Base64URL roundtrip root_cid mismatch")
	}
}

// ============================================================
// ParseAndValidate 便捷函数测试
// ============================================================

func TestParseAndValidate_Valid(t *testing.T) {
	jsonBytes, _ := validMeta().ToJSON()
	_, err := ParseAndValidate(jsonBytes)
	if err != nil {
		t.Errorf("ParseAndValidate should pass for valid metadata: %v", err)
	}
}

func TestParseAndValidate_Invalid(t *testing.T) {
	_, err := ParseAndValidate([]byte(`{"version": 99}`))
	if err == nil {
		t.Fatal("ParseAndValidate should fail for invalid metadata")
	}
}

func TestParseAndValidateBase64URL_Valid(t *testing.T) {
	encoded, _ := validMeta().ToBase64URL()
	_, err := ParseAndValidateBase64URL(encoded)
	if err != nil {
		t.Errorf("ParseAndValidateBase64URL should pass: %v", err)
	}
}

// ============================================================
// ValidateTags 测试
// ============================================================

func TestValidateTags_Empty(t *testing.T) {
	err := ValidateTags([]Tag{})
	if err == nil {
		t.Fatal("Expected error for empty tags")
	}
}

func TestValidateTags_MissingProtocol(t *testing.T) {
	tags := []Tag{
		{Name: "Protocol-Version", Value: "1"},
	}
	err := ValidateTags(tags)
	if err == nil {
		t.Fatal("Expected error for missing Protocol tag")
	}
}

func TestValidateTags_WrongProtocol(t *testing.T) {
	tags := []Tag{
		{Name: "Protocol", Value: "Wrong-Protocol"},
		{Name: "Protocol-Version", Value: "1"},
	}
	err := ValidateTags(tags)
	if err == nil {
		t.Fatal("Expected error for wrong Protocol tag")
	}
}

func TestValidateTags_MissingProtocolVersion(t *testing.T) {
	tags := []Tag{
		{Name: "Protocol", Value: "IPFS-Arweave-Bridge"},
	}
	err := ValidateTags(tags)
	if err == nil {
		t.Fatal("Expected error for missing Protocol-Version tag")
	}
}

func TestValidateTags_WrongProtocolVersion(t *testing.T) {
	tags := []Tag{
		{Name: "Protocol", Value: "IPFS-Arweave-Bridge"},
		{Name: "Protocol-Version", Value: "99"},
	}
	err := ValidateTags(tags)
	if err == nil {
		t.Fatal("Expected error for wrong Protocol-Version tag")
	}
}

func TestValidateTags_ValidMetaTags(t *testing.T) {
	tags := BuildMetaTags("bafyTestCID", "txID_12345678901234567890123456789012345678901")
	err := ValidateTags(tags)
	if err != nil {
		t.Errorf("Valid meta tags should pass: %v", err)
	}
}

func TestValidateTags_ValidCARTags(t *testing.T) {
	tags := BuildCARTags("bafyTestCID", 12345)
	err := ValidateTags(tags)
	if err != nil {
		t.Errorf("Valid CAR tags should pass: %v", err)
	}
}

func TestValidateTags_MetaTagsMissingRootCID(t *testing.T) {
	tags := []Tag{
		{Name: "Protocol", Value: "IPFS-Arweave-Bridge"},
		{Name: "Protocol-Version", Value: "1"},
		{Name: "IPFAR-Type", Value: "meta"},
		{Name: "Content-Type", Value: "application/json"},
		// Missing Root-CID
		{Name: "Data-TXID", Value: "tx123"},
	}
	err := ValidateTags(tags)
	if err == nil {
		t.Fatal("Expected error for meta tags missing Root-CID")
	}
}

func TestValidateTags_MetaTagsMissingDataTXID(t *testing.T) {
	tags := []Tag{
		{Name: "Protocol", Value: "IPFS-Arweave-Bridge"},
		{Name: "Protocol-Version", Value: "1"},
		{Name: "IPFAR-Type", Value: "meta"},
		{Name: "Content-Type", Value: "application/json"},
		{Name: "Root-CID", Value: "bafyTestCID"},
		// Missing Data-TXID
	}
	err := ValidateTags(tags)
	if err == nil {
		t.Fatal("Expected error for meta tags missing Data-TXID")
	}
}

func TestValidateTags_CARTagsMissingRootCID(t *testing.T) {
	tags := []Tag{
		{Name: "Protocol", Value: "IPFS-Arweave-Bridge"},
		{Name: "Protocol-Version", Value: "1"},
		{Name: "Content-Type", Value: "application/vnd.ipld.car"},
		// Missing Root-CID
		{Name: "Data-Size", Value: "12345"},
	}
	err := ValidateTags(tags)
	if err == nil {
		t.Fatal("Expected error for CAR tags missing Root-CID")
	}
}

func TestValidateTags_CARTagsMissingDataSize(t *testing.T) {
	tags := []Tag{
		{Name: "Protocol", Value: "IPFS-Arweave-Bridge"},
		{Name: "Protocol-Version", Value: "1"},
		{Name: "Content-Type", Value: "application/vnd.ipld.car"},
		{Name: "Root-CID", Value: "bafyTestCID"},
		// Missing Data-Size
	}
	err := ValidateTags(tags)
	if err == nil {
		t.Fatal("Expected error for CAR tags missing Data-Size")
	}
}

func TestValidateTags_GenericOnly(t *testing.T) {
	// 仅有通用 Tags，没有特定类型 Tags - 应该通过
	tags := []Tag{
		{Name: "Protocol", Value: "IPFS-Arweave-Bridge"},
		{Name: "Protocol-Version", Value: "1"},
	}
	err := ValidateTags(tags)
	if err != nil {
		t.Errorf("Generic-only tags should pass: %v", err)
	}
}

// ============================================================
// BuildMetaTags / BuildCARTags 测试
// ============================================================

func TestBuildMetaTags(t *testing.T) {
	tags := BuildMetaTags("bafyTestCID", "tx123")
	if len(tags) != 6 {
		t.Errorf("BuildMetaTags should return 6 tags, got %d", len(tags))
	}

	tagMap := TagSlice(tags).ToMap()
	if tagMap["Protocol"] != "IPFS-Arweave-Bridge" {
		t.Error("Protocol tag mismatch")
	}
	if tagMap["IPFAR-Type"] != "meta" {
		t.Error("IPFAR-Type tag should be 'meta'")
	}
	if tagMap["Content-Type"] != "application/json" {
		t.Error("Content-Type tag should be 'application/json'")
	}
}

func TestBuildCARTags(t *testing.T) {
	tags := BuildCARTags("bafyTestCID", 12345)
	if len(tags) != 5 {
		t.Errorf("BuildCARTags should return 5 tags, got %d", len(tags))
	}

	tagMap := TagSlice(tags).ToMap()
	if tagMap["Content-Type"] != "application/vnd.ipld.car" {
		t.Error("Content-Type tag should be 'application/vnd.ipld.car'")
	}
	if tagMap["Data-Size"] != "12345" {
		t.Errorf("Data-Size tag mismatch: got %s", tagMap["Data-Size"])
	}
}

// ============================================================
// CleanCID 测试
// ============================================================

func TestCleanCID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"bafytest", "bafytest"},
		{"  bafytest  ", "bafytest"},
		{"\"bafytest\"", "bafytest"},
		{"  \"bafytest\"  ", "bafytest"},
	}

	for _, tt := range tests {
		result := CleanCID(tt.input)
		if result != tt.expected {
			t.Errorf("CleanCID(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

// ============================================================
// JSON omitempty 测试
// ============================================================

func TestJSONOmitEmpty(t *testing.T) {
	meta := Metadata{
		Version:    1,
		Method:     "raw",
		RootCID:    "bafytest",
		DataTXID:   "tx123",
		DataHeight: 100,
		DataSize:   200000000,
	}

	jsonBytes, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	jsonStr := string(jsonBytes)

	// 大文件不包含 PoW 字段
	if strings.Contains(jsonStr, `"pow"`) {
		t.Error("PoW field should be omitted for large file")
	}
	if strings.Contains(jsonStr, `"pow_alg"`) {
		t.Error("pow_alg field should be omitted when empty")
	}

	// reference 不应该出现
	if strings.Contains(jsonStr, `"reference"`) {
		t.Error("reference field should be omitted when nil")
	}
}

// ============================================================
// 跨模块场景测试 — metadata + PoW 协同
// ============================================================

func TestMetadataPoWIntegration(t *testing.T) {
	// 模拟：解析 metadata 后判断是否需要 PoW
	meta := validMeta()
	meta.DataSize = 50 * 1024 * 1024 // 50 MiB

	if !meta.NeedsPoW() {
		t.Fatal("50 MiB file should need PoW")
	}

	// PoW 字段应存在
	meta.PoW = "42"
	meta.PoWAlg = "argon2id-light-v1"

	if err := meta.Validate(); err != nil {
		t.Errorf("Metadata with PoW should validate: %v", err)
	}
}

// ============================================================
// TagSlice 测试
// ============================================================

func TestTagSlice_ToMap(t *testing.T) {
	ts := TagSlice{
		{Name: "Key1", Value: "Val1"},
		{Name: "Key2", Value: "Val2"},
	}
	m := ts.ToMap()
	if len(m) != 2 {
		t.Errorf("ToMap should return 2 entries, got %d", len(m))
	}
	if m["Key1"] != "Val1" {
		t.Error("Key1 value mismatch")
	}
}

func TestTagSlice_EmptyToMap(t *testing.T) {
	ts := TagSlice{}
	m := ts.ToMap()
	if len(m) != 0 {
		t.Errorf("Empty TagSlice ToMap should return empty map, got %d entries", len(m))
	}
}

// ============================================================
// 辅助函数
// ============================================================

// validMeta 返回一个有效的 Metadata 实例
func validMeta() *Metadata {
	return &Metadata{
		Version:    1,
		Method:     "raw",
		RootCID:    "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
		DataTXID:   "arweave_tx_id_1234567890123456789012345678901234567890",
		DataHeight: 1913000,
		DataSize:   150 * 1024 * 1024, // 150 MiB，不需要 PoW
		PoW:        "",
		PoWAlg:     "",
	}
}
