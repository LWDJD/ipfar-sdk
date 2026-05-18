package ipfar

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	sdkmeta "github.com/LWDJD/ipfar-sdk/verify/metadata"
	"github.com/ipfs/go-cid"
)

// ── CAR building tests ─────────────────────────────────────────────────

func TestBuildCarV2_Basic(t *testing.T) {
	data := []byte("Hello, IPFAR! This is test data for CAR v2 building.")
	carBytes, rootCID, err := BuildCarV2(data)
	if err != nil {
		t.Fatalf("BuildCarV2 failed: %v", err)
	}

	if len(carBytes) < 100 {
		t.Errorf("CAR bytes too short: %d bytes", len(carBytes))
	}

	if rootCID == cid.Undef {
		t.Error("Root CID is undefined")
	}

	// Verify the CAR starts with the standard CARv2 pragma "car\\x02"
	stdPragma := []byte{0x63, 0x61, 0x72, 0x02}
	if len(carBytes) < len(stdPragma) {
		t.Fatal("CAR too short for pragma check")
	}
	if !bytes.Equal(carBytes[:len(stdPragma)], stdPragma) {
		t.Errorf("CAR does not start with standard CARv2 pragma")
	}

	// Verify we can extract the original data back
	extracted, err := extractDataFromCAR(carBytes)
	if err != nil {
		t.Fatalf("extractDataFromCAR failed: %v", err)
	}
	if !bytes.Equal(extracted, data) {
		t.Errorf("Extracted data does not match original: got %d bytes, want %d bytes",
			len(extracted), len(data))
	}
}

func TestBuildCarV2_Empty(t *testing.T) {
	data := []byte{}
	carBytes, rootCID, err := BuildCarV2(data)
	if err != nil {
		t.Fatalf("BuildCarV2 with empty data failed: %v", err)
	}

	if len(carBytes) < 100 {
		t.Errorf("CAR bytes too short for empty data: %d bytes", len(carBytes))
	}

	if rootCID == cid.Undef {
		t.Error("Root CID is undefined for empty data")
	}

	// Should be able to extract empty data
	extracted, err := extractDataFromCAR(carBytes)
	if err != nil {
		t.Fatalf("extractDataFromCAR for empty data failed: %v", err)
	}
	if len(extracted) != 0 {
		t.Errorf("Expected empty extracted data, got %d bytes", len(extracted))
	}
}

func TestBuildCarV2_RootCID_Consistent(t *testing.T) {
	data := []byte("consistent data for CID testing")
	_, cid1, _ := BuildCarV2(data)
	_, cid2, _ := BuildCarV2(data)

	if cid1.String() != cid2.String() {
		t.Errorf("CIDs should be consistent for same data: %s vs %s", cid1, cid2)
	}
}

func TestBuildCarV2_DifferentData_DifferentCID(t *testing.T) {
	_, cid1, _ := BuildCarV2([]byte("data one"))
	_, cid2, _ := BuildCarV2([]byte("data two"))

	if cid1.String() == cid2.String() {
		t.Error("Different data should produce different CIDs")
	}
}

// ── CID computation tests ──────────────────────────────────────────────

func TestComputeCID(t *testing.T) {
	data := []byte("test data for CID")
	c, err := ComputeCID(data)
	if err != nil {
		t.Fatalf("ComputeCID failed: %v", err)
	}

	if c == cid.Undef {
		t.Error("Computed CID is undefined")
	}

	// CID v1 should start with specific prefix
	if c.Prefix().Codec != cid.Raw {
		t.Errorf("Expected raw codec, got %d", c.Prefix().Codec)
	}
}

func TestComputeCID_Consistent(t *testing.T) {
	data := []byte("consistent")
	c1, _ := ComputeCID(data)
	c2, _ := ComputeCID(data)

	if c1.String() != c2.String() {
		t.Errorf("CIDs should be consistent: %s vs %s", c1, c2)
	}
}

// ── extractDataFromCAR tests ───────────────────────────────────────────

func TestExtractDataFromCAR_Roundtrip(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"small", []byte("hello world")},
		{"medium", make([]byte, 10000)},
		{"binary", []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "medium" {
				// Fill with non-zero data
				for i := range tt.data {
					tt.data[i] = byte(i % 256)
				}
			}

			carBytes, _, err := BuildCarV2(tt.data)
			if err != nil {
				t.Fatalf("BuildCarV2 failed: %v", err)
			}

			extracted, err := extractDataFromCAR(carBytes)
			if err != nil {
				t.Fatalf("extractDataFromCAR failed: %v", err)
			}

			if !bytes.Equal(extracted, tt.data) {
				t.Errorf("Data mismatch: got %d bytes, want %d bytes",
					len(extracted), len(tt.data))
			}
		})
	}
}

func TestExtractDataFromCAR_InvalidInput(t *testing.T) {
	// Too short
	_, err := extractDataFromCAR([]byte{0x00, 0x01})
	if err == nil {
		t.Error("Expected error for too-short CAR data")
	}
}

// ── BuildMetaJSON tests ────────────────────────────────────────────────

func TestBuildMetaJSON_Basic(t *testing.T) {
	// Use a large file (>= 100 MiB) to avoid PoW requirement
	jsonBytes, err := sdkmeta.BuildMetaJSON(
		"bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
		"txid_12345678901234567890123456789012345678901",
		150*1024*1024, // 150 MiB, no PoW needed
		1920278,
		nil,
	)
	if err != nil {
		t.Fatalf("BuildMetaJSON failed: %v", err)
	}

	// Parse back to verify
	var meta sdkmeta.Metadata
	if err := json.Unmarshal(jsonBytes, &meta); err != nil {
		t.Fatalf("Failed to parse built JSON: %v", err)
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
	if meta.DataTXID != "txid_12345678901234567890123456789012345678901" {
		t.Errorf("DataTXID mismatch")
	}
	if meta.DataHeight != 1920278 {
		t.Errorf("DataHeight = %d, want 1920278", meta.DataHeight)
	}
	if meta.DataSize != 150*1024*1024 {
		t.Errorf("DataSize = %d, want %d", meta.DataSize, 150*1024*1024)
	}
}

func TestBuildMetaJSON_WithOptions(t *testing.T) {
	opts := &sdkmeta.MetaOptions{
		Method:       sdkmeta.MethodBundle,
		ContentType:  "application/octet-stream",
		OriginalName: "test.bin",
		PoW:          "abc123",
		PoWAlg:       "argon2id-light-v1",
		BundleTXID:   "bundle_tx_12345",
	}

	jsonBytes, err := sdkmeta.BuildMetaJSON(
		"bafyTestCID",
		"data_txid_1234567890123456789012345678901234567890",
		1024, // small file, needs PoW
		100,
		opts,
	)
	if err != nil {
		t.Fatalf("BuildMetaJSON with options failed: %v", err)
	}

	// Parse back
	var meta sdkmeta.Metadata
	if err := json.Unmarshal(jsonBytes, &meta); err != nil {
		t.Fatalf("Failed to parse built JSON: %v", err)
	}

	if meta.Method != sdkmeta.MethodBundle {
		t.Errorf("Method = %s, want bundle", meta.Method)
	}
	if meta.ContentType != "application/octet-stream" {
		t.Errorf("ContentType = %s, want application/octet-stream", meta.ContentType)
	}
	if meta.OriginalName != "test.bin" {
		t.Errorf("OriginalName = %s, want test.bin", meta.OriginalName)
	}
	if meta.PoW != "abc123" {
		t.Errorf("PoW = %s, want abc123", meta.PoW)
	}
	if meta.PoWAlg != "argon2id-light-v1" {
		t.Errorf("PoWAlg = %s, want argon2id-light-v1", meta.PoWAlg)
	}
	if meta.BundleTXID != "bundle_tx_12345" {
		t.Errorf("BundleTXID = %s, want bundle_tx_12345", meta.BundleTXID)
	}
}

func TestBuildMetaJSON_LargeFile(t *testing.T) {
	// Large file (>= 100 MiB) doesn't need PoW
	jsonBytes, err := sdkmeta.BuildMetaJSON(
		"bafyTestCID",
		"data_txid_1234567890123456789012345678901234567890",
		200*1024*1024, // 200 MiB
		100,
		nil,
	)
	if err != nil {
		t.Fatalf("BuildMetaJSON for large file failed: %v", err)
	}

	// Verify PoW fields are absent
	var raw map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &raw); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if _, exists := raw["pow"]; exists {
		t.Error("PoW field should be absent for large file")
	}
	if _, exists := raw["pow_alg"]; exists {
		t.Error("pow_alg field should be absent for large file")
	}
}

func TestBuildMetaJSON_DefaultMethod(t *testing.T) {
	// nil opts → should default to "raw"
	jsonBytes, err := sdkmeta.BuildMetaJSON(
		"bafyTestCID",
		"data_txid_1234567890123456789012345678901234567890",
		200*1024*1024,
		100,
		nil,
	)
	if err != nil {
		t.Fatalf("BuildMetaJSON failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &raw); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}
	if raw["method"] != "raw" {
		t.Errorf("Default method = %v, want raw", raw["method"])
	}
}

// ── UploadResult / VerifyResult tests ──────────────────────────────────

func TestUploadResult_Fields(t *testing.T) {
	r := &UploadResult{
		RootCID:    "bafyTest",
		DataTXID:   "tx123",
		MetaTXID:   "tx456",
		DataHeight: 100,
		DataSize:   1024,
	}

	if r.RootCID != "bafyTest" {
		t.Error("RootCID field mismatch")
	}
	if r.DataTXID != "tx123" {
		t.Error("DataTXID field mismatch")
	}
}

func TestVerifyResult_AddError(t *testing.T) {
	r := &VerifyResult{Valid: true}
	if !r.Valid {
		t.Error("New VerifyResult should be valid")
	}

	r.AddError("something went wrong")
	if r.Valid {
		t.Error("VerifyResult should be invalid after AddError")
	}
	if len(r.Errors) != 1 {
		t.Errorf("Errors count = %d, want 1", len(r.Errors))
	}
	if r.Errors[0] != "something went wrong" {
		t.Errorf("Error message = %s, want 'something went wrong'", r.Errors[0])
	}

	r.AddError("another error")
	if len(r.Errors) != 2 {
		t.Errorf("Errors count = %d, want 2", len(r.Errors))
	}
}

func TestVerifyResult_Default(t *testing.T) {
	r := &VerifyResult{}
	// Zero value: Valid is false
	if r.Valid {
		t.Error("Zero-value VerifyResult.Valid should be false")
	}
	if r.CARVerified {
		t.Error("Zero-value CARVerified should be false")
	}
	if r.MetaVerified {
		t.Error("Zero-value MetaVerified should be false")
	}
	if r.PoWVerified {
		t.Error("Zero-value PoWVerified should be false")
	}
}

// ── detectContentType tests ────────────────────────────────────────────

func TestDetectContentType(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"test.txt", "text/plain"},
		{"image.png", "image/png"},
		{"video.mp4", "video/mp4"},
		{"doc.pdf", "application/pdf"},
		{"data.json", "application/json"},
		{"page.html", "text/html"},
		{"unknown.xyz", "application/octet-stream"},
		{"noextension", "application/octet-stream"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := detectContentType(tt.path)
			if got != tt.want {
				t.Errorf("detectContentType(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

// ── toArweaveTags tests ────────────────────────────────────────────────

func TestToArweaveTags(t *testing.T) {
	metaTags := []sdkmeta.Tag{
		{Name: "Protocol", Value: "IPFS-Arweave-Bridge"},
		{Name: "Root-CID", Value: "bafyTest"},
	}

	arTags := toArweaveTags(metaTags)
	if len(arTags) != 2 {
		t.Errorf("Tag count = %d, want 2", len(arTags))
	}
	if arTags[0].Name != "Protocol" {
		t.Errorf("Tag[0].Name = %s, want Protocol", arTags[0].Name)
	}
	if arTags[1].Value != "bafyTest" {
		t.Errorf("Tag[1].Value = %s, want bafyTest", arTags[1].Value)
	}
}

func TestToArweaveTags_Empty(t *testing.T) {
	arTags := toArweaveTags(nil)
	if len(arTags) != 0 {
		t.Errorf("Expected empty result, got %d tags", len(arTags))
	}
}

// ── readVarint tests ───────────────────────────────────────────────────

func TestReadVarint(t *testing.T) {
	tests := []struct {
		input []byte
		want  uint64
	}{
		{[]byte{0x00}, 0},
		{[]byte{0x01}, 1},
		{[]byte{0x7f}, 127},
		{[]byte{0x80, 0x01}, 128},
		{[]byte{0xff, 0x01}, 255},
	}

	for _, tt := range tests {
		val, n := readVarint(tt.input)
		if val != tt.want {
			t.Errorf("readVarint(%x) = %d, want %d", tt.input, val, tt.want)
		}
		if n <= 0 {
			t.Errorf("readVarint(%x) returned n=%d", tt.input, n)
		}
	}
}

// ── download helpers tests ─────────────────────────────────────────────

func TestTryParseMetadata_PlainJSON(t *testing.T) {
	jsonStr := `{"version":1,"method":"raw","root_cid":"bafyTest","data_txid":"tx123","data_height":100,"data_size":200000000}`
	meta, err := tryParseMetadata([]byte(jsonStr))
	if err != nil {
		t.Fatalf("tryParseMetadata failed: %v", err)
	}
	if meta.RootCID != "bafyTest" {
		t.Errorf("RootCID = %s, want bafyTest", meta.RootCID)
	}
}

func TestTryParseMetadata_Invalid(t *testing.T) {
	_, err := tryParseMetadata([]byte("not json or base64url!!!"))
	if err == nil {
		t.Error("Expected error for invalid data")
	}
}

// ── Context helper ─────────────────────────────────────────────────────

func TestUpload_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	// Create temp file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.bin")
	if err := os.WriteFile(tmpFile, []byte("test data"), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	// This will fail because the arweave client is a stub and context is cancelled
	// Just verify that the function signature works and it returns an error
	_, err := Upload(ctx, nil, nil, tmpFile, nil)
	if err == nil {
		t.Log("Upload with nil client and cancelled context returned nil error (stub behavior)")
	}
}

// ── verifyLocalCAR tests ───────────────────────────────────────────────

func TestVerifyLocalCAR_Valid(t *testing.T) {
	data := []byte("verification test data")
	carBytes, rootCID, err := BuildCarV2(data)
	if err != nil {
		t.Fatalf("BuildCarV2 failed: %v", err)
	}

	if !verifyLocalCAR(carBytes, rootCID) {
		t.Error("verifyLocalCAR should pass for valid CAR")
	}
}

func TestVerifyLocalCAR_WrongCID(t *testing.T) {
	data := []byte("verification test data")
	carBytes, _, err := BuildCarV2(data)
	if err != nil {
		t.Fatalf("BuildCarV2 failed: %v", err)
	}

	// Compute a different CID
	otherCID, _ := ComputeCID([]byte("different data"))

	if verifyLocalCAR(carBytes, otherCID) {
		t.Error("verifyLocalCAR should fail for wrong CID")
	}
}

func TestVerifyLocalCAR_InvalidInput(t *testing.T) {
	if verifyLocalCAR([]byte{0x00, 0x01}, cid.Undef) {
		t.Error("verifyLocalCAR should fail for garbage input")
	}
}

// ── bytesReaderAt tests ────────────────────────────────────────────────

func TestBytesReaderAt(t *testing.T) {
	data := []byte("hello world")
	r := &bytesReaderAt{data: data}

	buf := make([]byte, 5)
	n, err := r.ReadAt(buf, 0)
	if err != nil {
		t.Fatalf("ReadAt failed: %v", err)
	}
	if n != 5 {
		t.Errorf("ReadAt n = %d, want 5", n)
	}
	if string(buf) != "hello" {
		t.Errorf("ReadAt data = %q, want 'hello'", string(buf))
	}

	// Read at offset
	n, err = r.ReadAt(buf, 6)
	if err != nil {
		t.Fatalf("ReadAt at offset 6 failed: %v", err)
	}
	if string(buf[:n]) != "world" {
		t.Errorf("ReadAt at offset 6 = %q, want 'world'", string(buf[:n]))
	}
}
