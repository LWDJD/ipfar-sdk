package pow

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestNeedsPoW(t *testing.T) {
	tests := []struct {
		size     int64
		expected bool
	}{
		{0, true},
		{1024, true},
		{100*1024*1024 - 1, true},
		{100 * 1024 * 1024, false},
		{100*1024*1024 + 1, false},
		{1024 * 1024 * 1024, false},
	}

	for _, tt := range tests {
		result := NeedsPoW(tt.size)
		if result != tt.expected {
			t.Errorf("NeedsPoW(%d) = %v, want %v", tt.size, result, tt.expected)
		}
	}
}

func TestDefaultWorkers(t *testing.T) {
	n := DefaultWorkers()
	if n < 1 {
		t.Errorf("DefaultWorkers() = %d, want at least 1", n)
	}
	if n > 10 {
		t.Errorf("DefaultWorkers() = %d, want at most 10", n)
	}
	t.Logf("DefaultWorkers() = %d", n)
}

func TestComputePoW_ValidSalt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PoW computation in short mode")
	}

	rootCID := "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
	dataTXID := "test-txid-valid-salt"

	ctx := context.Background()
	var lastProgress ProgressInfo
	salt, err := ComputePoW(ctx, rootCID, dataTXID, 10, func(info ProgressInfo) {
		lastProgress = info
	})
	if err != nil {
		t.Fatalf("ComputePoW failed: %v", err)
	}

	if salt == "" {
		t.Fatal("empty salt returned")
	}

	// Salt must be a decimal string.
	for _, c := range salt {
		if c < '0' || c > '9' {
			t.Fatalf("non-digit character in salt: %c", c)
		}
	}

	// Salt must be a valid uint64.
	_, err = strconv.ParseUint(salt, 10, 64)
	if err != nil {
		t.Fatalf("salt %q is not a valid uint64: %v", salt, err)
	}

	t.Logf("Found salt: %s (attempts: %d)", salt, lastProgress.Attempts)
}

func TestComputePoW_ProgressCallback(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PoW computation in short mode")
	}

	rootCID := "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
	dataTXID := "test-progress-callback"

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	var maxAttempts uint64
	salt, err := ComputePoW(ctx, rootCID, dataTXID, 10, func(info ProgressInfo) {
		if info.Attempts > maxAttempts {
			maxAttempts = info.Attempts
		}
	})
	if err != nil {
		t.Fatalf("ComputePoW failed: %v", err)
	}

	if salt == "" {
		t.Fatal("empty salt")
	}

	if maxAttempts == 0 {
		t.Error("progress callback reported 0 attempts")
	}

	t.Logf("Found salt=%s, max attempts reported=%d", salt, maxAttempts)
}

func TestComputePoW_Cancellation(t *testing.T) {
	rootCID := "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
	dataTXID := "test-cancel"

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately cancel

	_, err := ComputePoW(ctx, rootCID, dataTXID, 4, nil)
	if err != ErrPoWCancelled {
		t.Errorf("expected ErrPoWCancelled, got %v", err)
	}
}

func TestComputePoW_Timeout(t *testing.T) {
	rootCID := "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
	dataTXID := "test-timeout"

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	var attempts uint64
	_, err := ComputePoW(ctx, rootCID, dataTXID, 4, func(info ProgressInfo) {
		attempts = info.Attempts
	})

	if err != ErrPoWCancelled {
		t.Errorf("expected ErrPoWCancelled, got %v", err)
	}
	t.Logf("Cancelled after ~%d attempts (200ms timeout)", attempts)
}

func TestComputePoW_MultipleWorkers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PoW computation in short mode")
	}

	rootCID := "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
	dataTXID := "test-multi-worker"

	// Run with 10 workers.
	salt, err := ComputePoW(context.Background(), rootCID, dataTXID, 10, nil)
	if err != nil {
		t.Fatalf("ComputePoW with 4 workers failed: %v", err)
	}

	if salt == "" {
		t.Fatal("empty salt")
	}

	// Salt must be valid decimal.
	_, err = strconv.ParseUint(salt, 10, 64)
	if err != nil {
		t.Fatalf("salt %q is not a valid uint64: %v", salt, err)
	}

	t.Logf("10 workers found salt=%s", salt)
}

func TestComputePoW_NilProgress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PoW computation in short mode")
	}

	rootCID := "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
	dataTXID := "test-nil-progress"

	salt, err := ComputePoW(context.Background(), rootCID, dataTXID, 2, nil)
	if err != nil {
		t.Fatalf("ComputePoW with nil progress failed: %v", err)
	}

	if salt == "" {
		t.Fatal("empty salt")
	}

	t.Logf("Found salt with nil progress: %s", salt)
}

func TestHasLeadingZeroBytes(t *testing.T) {
	tests := []struct {
		data     []byte
		n        int
		expected bool
	}{
		{[]byte{0, 0, 1, 2}, 2, true},
		{[]byte{0, 0, 0, 0}, 4, true},
		{[]byte{0, 1, 0, 0}, 2, false},
		{[]byte{1, 0, 0, 0}, 1, false},
		{[]byte{0, 0}, 3, false},
		{[]byte{}, 1, false},
	}

	for _, tt := range tests {
		result := hasLeadingZeroBytes(tt.data, tt.n)
		if result != tt.expected {
			t.Errorf("hasLeadingZeroBytes(%v, %d) = %v, want %v", tt.data, tt.n, result, tt.expected)
		}
	}
}

func TestFormatSpeed(t *testing.T) {
	tests := []struct {
		hps      float64
		expected string
	}{
		{500, "500 h/s"},
		{1500, "1.5 K/s"},
		{1_500_000, "1.5 M/s"},
		{0, "0 h/s"},
	}

	for _, tt := range tests {
		result := FormatSpeed(tt.hps)
		if result != tt.expected {
			t.Errorf("FormatSpeed(%f) = %q, want %q", tt.hps, result, tt.expected)
		}
	}
}

func TestFormatNumber(t *testing.T) {
	tests := []struct {
		n        uint64
		expected string
	}{
		{0, "0"},
		{100, "100"},
		{1000, "1,000"},
		{1000000, "1,000,000"},
		{1234567890, "1,234,567,890"},
	}

	for _, tt := range tests {
		result := FormatNumber(tt.n)
		if result != tt.expected {
			t.Errorf("FormatNumber(%d) = %q, want %q", tt.n, result, tt.expected)
		}
	}
}

// =============================================================================
// Cache tests
// =============================================================================

func TestPoWCache_SaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "test.pow.json")

	rootCID := "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
	dataTXID := "test-cache-txid"
	salt := "12345"

	// Initially nothing is cached.
	_, ok := LoadPoWCache(cachePath, rootCID, dataTXID)
	if ok {
		t.Fatal("expected cache miss before save")
	}

	// Save cache.
	err := SavePoWCache(cachePath, rootCID, dataTXID, salt)
	if err != nil {
		t.Fatalf("SavePoWCache failed: %v", err)
	}

	// Load cache.
	loaded, ok := LoadPoWCache(cachePath, rootCID, dataTXID)
	if !ok {
		t.Fatal("expected cache hit after save")
	}
	if loaded != salt {
		t.Errorf("expected salt %q, got %q", salt, loaded)
	}
}

func TestPoWCache_Mismatch(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "test_mismatch.pow.json")

	rootCID := "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
	dataTXID := "test-cache-txid"
	salt := "12345"

	err := SavePoWCache(cachePath, rootCID, dataTXID, salt)
	if err != nil {
		t.Fatalf("SavePoWCache failed: %v", err)
	}

	// Different rootCID — should miss.
	_, ok := LoadPoWCache(cachePath, "different-root-cid", dataTXID)
	if ok {
		t.Error("expected cache miss for different rootCID")
	}

	// Different dataTXID — should miss.
	_, ok = LoadPoWCache(cachePath, rootCID, "different-data-txid")
	if ok {
		t.Error("expected cache miss for different dataTXID")
	}

	// Non-existent file — should miss.
	_, ok = LoadPoWCache("/nonexistent/path.pow.json", rootCID, dataTXID)
	if ok {
		t.Error("expected cache miss for non-existent file")
	}
}

func TestPoWCache_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "invalid.pow.json")

	// Write invalid JSON.
	err := os.WriteFile(cachePath, []byte("not json"), 0644)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	_, ok := LoadPoWCache(cachePath, "any", "any")
	if ok {
		t.Error("expected cache miss for invalid JSON")
	}
}
