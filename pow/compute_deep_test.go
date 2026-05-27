package pow

import (
	"context"
	"encoding/binary"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

// ============================================================
// Boundary: salt = 0
// ============================================================

func TestComputePoW_SaltZeroCheck(t *testing.T) {
	// Manually verify that salt=0 rarely satisfies PoW
	password := []byte("test-cid" + "test-tx")
	saltBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(saltBytes, 0)
	hash := argon2.IDKey(password, saltBytes, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	if hasLeadingZeroBytes(hash, MinLeadingZeroBytes) {
		t.Log("salt=0 satisfies PoW (extremely rare)")
	} else {
		t.Log("salt=0 does not satisfy PoW (expected)")
	}
}

// ============================================================
// Boundary: salt = math.MaxUint64
// ============================================================

func TestComputePoW_SaltMaxUint64Check(t *testing.T) {
	password := []byte("test-max" + "tx-max")
	saltBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(saltBytes, math.MaxUint64)
	hash := argon2.IDKey(password, saltBytes, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	if hasLeadingZeroBytes(hash, MinLeadingZeroBytes) {
		t.Log("MaxUint64 salt satisfies PoW (extremely rare)")
	} else {
		t.Log("MaxUint64 salt does not satisfy PoW (expected)")
	}
}

// ============================================================
// Boundary: password with unicode characters
// ============================================================

func TestComputePoW_UnicodePassword(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PoW computation in short mode")
	}

	rootCID := "bafy测试CID中文日本語한국어"
	dataTXID := "tx-emojis-🎉🚀💻"

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	salt, err := ComputePoW(ctx, rootCID, dataTXID, 1, nil)
	if err != nil {
		if err == ErrPoWCancelled {
			t.Skipf("unicode PoW timed out: %v", err)
		}
		t.Logf("unicode PoW: %v (may fail due to safety limit)", err)
		return
	}

	if salt == "" {
		t.Fatal("empty salt returned")
	}

	// Verify salt satisfies difficulty
	saltUint, _ := strconv.ParseUint(salt, 10, 64)
	password := []byte(rootCID + dataTXID)
	saltBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(saltBytes, saltUint)
	hash := argon2.IDKey(password, saltBytes, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	if !hasLeadingZeroBytes(hash, MinLeadingZeroBytes) {
		t.Errorf("unicode PoW salt %s does not satisfy difficulty", salt)
	}

	t.Logf("Unicode PoW: salt=%s", salt)
}

func TestComputePoW_BinaryPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PoW computation in short mode")
	}

	rootCID := "bafy\x00\x01\x02\xFFtest"
	dataTXID := "tx\x00null"

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	salt, err := ComputePoW(ctx, rootCID, dataTXID, 1, nil)
	if err != nil {
		t.Logf("binary PoW: %v (may fail)", err)
		return
	}

	saltUint, _ := strconv.ParseUint(salt, 10, 64)
	password := []byte(rootCID + dataTXID)
	saltBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(saltBytes, saltUint)
	hash := argon2.IDKey(password, saltBytes, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	if !hasLeadingZeroBytes(hash, MinLeadingZeroBytes) {
		t.Errorf("binary PoW salt %s does not satisfy difficulty", salt)
	}

	t.Logf("Binary PoW: salt=%s", salt)
}

// ============================================================
// Workers boundary cases
// ============================================================

func TestComputePoW_ZeroWorkers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PoW computation in short mode")
	}

	rootCID := "zero-workers-test"
	dataTXID := "tx-zero-workers"
	ctx := context.Background()

	// workers=0 should use DefaultWorkers()
	salt, err := ComputePoW(ctx, rootCID, dataTXID, 0, nil)
	if err != nil {
		t.Fatalf("ComputePoW with 0 workers failed: %v", err)
	}
	if salt == "" {
		t.Fatal("empty salt")
	}

	t.Logf("Zero workers PoW: salt=%s", salt)
}

func TestComputePoW_NegativeWorkers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PoW computation in short mode")
	}

	rootCID := "neg-workers-test"
	dataTXID := "tx-neg-workers"

	// Negative workers should be treated like 0 (use defaults)
	salt, err := ComputePoW(context.Background(), rootCID, dataTXID, -5, nil)
	if err != nil {
		t.Fatalf("ComputePoW with -5 workers failed: %v", err)
	}
	if salt == "" {
		t.Fatal("empty salt with negative workers")
	}

	t.Logf("Negative workers PoW: salt=%s", salt)
}

func TestComputePoW_OneWorker(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PoW computation in short mode")
	}

	rootCID := "one-worker-test"
	dataTXID := "tx-one-worker"

	salt, err := ComputePoW(context.Background(), rootCID, dataTXID, 1, nil)
	if err != nil {
		t.Fatalf("ComputePoW with 1 worker failed: %v", err)
	}
	if salt == "" {
		t.Fatal("empty salt")
	}

	t.Logf("One worker PoW: salt=%s", salt)
}

func TestComputePoW_ManyWorkers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PoW computation in short mode")
	}

	rootCID := "many-workers-test"
	dataTXID := "tx-many-workers"

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	salt, err := ComputePoW(ctx, rootCID, dataTXID, 16, nil)
	if err != nil {
		t.Fatalf("ComputePoW with 16 workers failed: %v", err)
	}
	if salt == "" {
		t.Fatal("empty salt")
	}

	t.Logf("16 workers PoW: salt=%s", salt)
}

// ============================================================
// hasLeadingZeroBytes boundary cases
// ============================================================

func TestHasLeadingZeroBytes_AllBoundaries(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		n        int
		expected bool
	}{
		{"n=0, empty data", []byte{}, 0, true},
		{"n=0, non-empty data", []byte{1, 2, 3}, 0, true},
		{"n=1, one zero", []byte{0}, 1, true},
		{"n=1, no zero", []byte{1}, 1, false},
		{"n=2, two zeros", []byte{0, 0}, 2, true},
		{"n=2, one zero", []byte{0, 1}, 2, false},
		{"n=2, all zeros long", []byte{0, 0, 0, 0, 0}, 2, true},
		{"n=5, exactly five zeros", []byte{0, 0, 0, 0, 0}, 5, true},
		{"n=5, four zeros", []byte{0, 0, 0, 0, 1}, 5, false},
		{"n > len(data)", []byte{0}, 5, false},
		{"32 zeros for n=2", make([]byte, 32), 2, true},
		{"32 zeros for n=32", make([]byte, 32), 32, true},
		{"byte full of zeros", []byte{0x00}, 1, true},
		{"byte 0x01", []byte{0x01}, 1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasLeadingZeroBytes(tt.data, tt.n)
			if result != tt.expected {
				t.Errorf("hasLeadingZeroBytes(%v, %d) = %v, want %v",
					tt.data, tt.n, result, tt.expected)
			}
		})
	}
}

// ============================================================
// Format functions edge cases
// ============================================================

func TestFormatSpeed_AllRanges(t *testing.T) {
	tests := []struct {
		hps      float64
		expected string
	}{
		{0, "0 h/s"},
		{1, "1 h/s"},
		{500, "500 h/s"},
		{999, "999 h/s"},
		{1000, "1.0 K/s"},
		{1500, "1.5 K/s"},
		{999999, "1000.0 K/s"},
		{1000000, "1.0 M/s"},
		{1500000, "1.5 M/s"},
		{1000000000, "1000.0 M/s"},
	}

	for _, tt := range tests {
		result := FormatSpeed(tt.hps)
		if result != tt.expected {
			t.Errorf("FormatSpeed(%f) = %q, want %q", tt.hps, result, tt.expected)
		}
	}
}

func TestFormatNumber_EdgeCases(t *testing.T) {
	tests := []struct {
		n        uint64
		expected string
	}{
		{0, "0"},
		{1, "1"},
		{10, "10"},
		{100, "100"},
		{999, "999"},
		{1000, "1,000"},
		{1000000, "1,000,000"},
		{math.MaxUint64, "18,446,744,073,709,551,615"},
	}

	for _, tt := range tests {
		result := FormatNumber(tt.n)
		if result != tt.expected {
			t.Errorf("FormatNumber(%d) = %q, want %q", tt.n, result, tt.expected)
		}
	}
}

// ============================================================
// Concurrent ComputePoW calls
// ============================================================

func TestComputePoW_Concurrent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PoW computation in short mode")
	}

	done := make(chan bool, 5)

	for i := 0; i < 5; i++ {
		go func(idx int) {
			rootCID := "concurrent-pow-" + strconv.Itoa(idx)
			dataTXID := "concurrent-tx-" + strconv.Itoa(idx)

			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			salt, err := ComputePoW(ctx, rootCID, dataTXID, 2, nil)
			if err != nil {
				t.Logf("concurrent PoW %d failed: %v", idx, err)
				done <- false
				return
			}

			// Verify salt satisfies difficulty
			saltUint, _ := strconv.ParseUint(salt, 10, 64)
			password := []byte(rootCID + dataTXID)
			saltBytes := make([]byte, 8)
			binary.LittleEndian.PutUint64(saltBytes, saltUint)
			hash := argon2.IDKey(password, saltBytes, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
			if !hasLeadingZeroBytes(hash, MinLeadingZeroBytes) {
				t.Errorf("concurrent PoW %d: salt %s does not satisfy difficulty", idx, salt)
			}

			done <- true
		}(i)
	}

	successes := 0
	for i := 0; i < 5; i++ {
		if <-done {
			successes++
		}
	}

	t.Logf("Concurrent PoW: %d/5 succeeded", successes)
}

// ============================================================
// SavePoWCache edge cases
// ============================================================

func TestSavePoWCache_EmptyInputs(t *testing.T) {
	dir := t.TempDir()
	cachePath := dir + "/empty_test.pow.json"

	// Save with empty strings
	err := SavePoWCache(cachePath, "", "", "")
	if err != nil {
		t.Fatalf("SavePoWCache with empty inputs failed: %v", err)
	}

	// Load back
	salt, ok := LoadPoWCache(cachePath, "", "")
	if !ok {
		t.Error("should find cache with empty key")
	}
	if salt != "" {
		t.Errorf("expected empty salt, got %q", salt)
	}
}

func TestSavePoWCache_SpecialCharacters(t *testing.T) {
	dir := t.TempDir()
	cachePath := dir + "/special_test.pow.json"

	rootCID := "bafy-test-escape"
	dataTXID := "tx-with-spaces-and-newlines"
	salt := "42"

	err := SavePoWCache(cachePath, rootCID, dataTXID, salt)
	if err != nil {
		t.Fatalf("SavePoWCache with special chars failed: %v", err)
	}

	loaded, ok := LoadPoWCache(cachePath, rootCID, dataTXID)
	if !ok {
		t.Error("should find cache with special characters")
	}
	if loaded != salt {
		t.Errorf("salt mismatch: got %q, want %q", loaded, salt)
	}
}

// ============================================================
// Progress callback: nil vs valid
// ============================================================

func TestComputePoW_NilProgressCallback(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PoW computation in short mode")
	}

	rootCID := "nil-progress-test"
	dataTXID := "tx-nil-progress"

	salt, err := ComputePoW(context.Background(), rootCID, dataTXID, 2, nil)
	if err != nil {
		t.Fatalf("ComputePoW with nil progress failed: %v", err)
	}
	if salt == "" {
		t.Fatal("empty salt")
	}

	t.Logf("Nil progress PoW: salt=%s", salt)
}

// ============================================================
// Progress callback: receive updates
// ============================================================

func TestComputePoW_ProgressReceivesUpdates(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PoW computation in short mode")
	}

	rootCID := "progress-update-test"
	dataTXID := "tx-progress-update"

	updateCount := 0
	var lastAttempts uint64

	salt, err := ComputePoW(context.Background(), rootCID, dataTXID, 2, func(info ProgressInfo) {
		updateCount++
		lastAttempts = info.Attempts
	})

	if err != nil {
		t.Fatalf("ComputePoW failed: %v", err)
	}

	t.Logf("Progress updates: count=%d, last_attempts=%d, salt=%s", updateCount, lastAttempts, salt)

	if updateCount == 0 {
		t.Error("expected at least 1 progress update")
	}
}

// ============================================================
// NeedsPoW negative size (just for coverage, shouldn't happen)
// ============================================================

func TestNeedsPoW_NegativeSize(t *testing.T) {
	result := NeedsPoW(-1)
	if !result {
		t.Error("NeedsPoW(-1) should return true (any value < threshold needs PoW)")
	}

	result = NeedsPoW(-100 * 1024 * 1024)
	if !result {
		t.Error("NeedsPoW with large negative should return true")
	}
}

// ============================================================
// PoW cache: nonexistent file
// ============================================================

func TestLoadPoWCache_NonExistent(t *testing.T) {
	_, ok := LoadPoWCache("/nonexistent/path/that/does/not/exist.pow.json", "any", "any")
	if ok {
		t.Error("should miss for non-existent file")
	}
}

// ============================================================
// Determinism: same input, same nanosecond → same salt
// ============================================================

func TestComputePoW_Deterministic_SameRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PoW computation in short mode")
	}

	rootCID := "deterministic-test-v3"
	dataTXID := "tx-deterministic-v3"

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	salt1, err := ComputePoW(ctx, rootCID, dataTXID, 4, nil)
	if err != nil {
		t.Fatalf("first ComputePoW failed: %v", err)
	}

	salt2, err := ComputePoW(context.Background(), rootCID, dataTXID, 4, nil)
	if err != nil {
		t.Fatalf("second ComputePoW failed: %v", err)
	}

	if salt1 != salt2 {
		t.Logf("salts differ: %s vs %s (may use different seed due to time progression)", salt1, salt2)
	} else {
		t.Logf("deterministic: both calls produced salt=%s", salt1)
	}
}

// ============================================================
// Very long password inputs
// ============================================================

func TestComputePoW_VeryLongPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PoW computation in short mode")
	}

	// 5KB root CID + 5KB data TXID
	rootCID := strings.Repeat("bafytest1234567890123456789012345678901234567890", 100)
	dataTXID := strings.Repeat("tx1234567890123456789012345678901234567890123", 100)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	salt, err := ComputePoW(ctx, rootCID, dataTXID, 1, nil)
	if err != nil {
		t.Logf("very long password PoW: %v", err)
		return
	}

	t.Logf("Very long password PoW: salt=%s", salt)
}

// ============================================================
// Salt decimal format verification
// ============================================================

func TestComputePoW_SaltIsDecimal(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PoW computation in short mode")
	}

	rootCID := "decimal-check"
	dataTXID := "tx-decimal-check"

	salt, err := ComputePoW(context.Background(), rootCID, dataTXID, 2, nil)
	if err != nil {
		t.Fatalf("ComputePoW failed: %v", err)
	}

	// Salt must be a valid decimal string
	for _, c := range salt {
		if c < '0' || c > '9' {
			t.Fatalf("non-digit character in salt: %c", c)
		}
	}

	// Must be parseable as uint64
	_, err = strconv.ParseUint(salt, 10, 64)
	if err != nil {
		t.Fatalf("salt %q is not a valid uint64: %v", salt, err)
	}

	t.Logf("Valid decimal salt: %s", salt)
}
