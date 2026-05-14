package pow

import (
	"context"
	"strconv"
	"testing"
)

// ============================================================
// NeedsPoW 测试
// ============================================================

func TestNeedsPoW_SmallFile(t *testing.T) {
	tests := []struct {
		name     string
		dataSize int64
		expected bool
	}{
		{"zero bytes", 0, true},
		{"1 byte", 1, true},
		{"1 KiB", 1024, true},
		{"1 MiB", 1024 * 1024, true},
		{"99 MiB", 99 * 1024 * 1024, true},
		{"100 MiB - 1 byte", PoWThreshold - 1, true},
		{"exactly 100 MiB", PoWThreshold, false},
		{"100 MiB + 1 byte", PoWThreshold + 1, false},
		{"1 GiB", 1024 * 1024 * 1024, false},
		{"10 GiB", 10 * 1024 * 1024 * 1024, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NeedsPoW(tt.dataSize)
			if result != tt.expected {
				t.Errorf("NeedsPoW(%d) = %v, want %v", tt.dataSize, result, tt.expected)
			}
		})
	}
}

func TestNeedsPoW_NegativeSize(t *testing.T) {
	// 负值在现实中不会出现，但确保不会 panic
	result := NeedsPoW(-1)
	if !result {
		t.Error("NeedsPoW(-1) should return true (any value < threshold needs PoW)")
	}
}

// ============================================================
// Verify 测试 — 算法不匹配
// ============================================================

func TestVerify_AlgorithmMismatch(t *testing.T) {
	err := Verify("12345", "wrong-algo", "bafyTestCID", "txID123", 1024)
	if err == nil {
		t.Fatal("expected error for wrong algorithm")
	}
	if !containsString(err.Error(), "mismatch") {
		t.Errorf("expected mismatch error, got: %v", err)
	}
}

func TestVerify_MissingAlgorithm(t *testing.T) {
	err := Verify("12345", "", "bafyTestCID", "txID123", 1024)
	if err == nil {
		t.Fatal("expected error for missing algorithm")
	}
}

// ============================================================
// Verify 测试 — 大文件免 PoW
// ============================================================

func TestVerify_LargeFileNoPoWNeeded(t *testing.T) {
	// 大文件即使 pow 为空、算法为空也应该跳过验证
	err := Verify("", "", "bafyTestCID", "txID123", PoWThreshold)
	if err != nil {
		t.Errorf("large file should skip PoW verification, got error: %v", err)
	}

	err = Verify("", "", "bafyTestCID", "txID123", PoWThreshold+1)
	if err != nil {
		t.Errorf("large file should skip PoW verification, got error: %v", err)
	}

	// 即使提供无效 pow 和无效算法，大文件也应该跳过
	err = Verify("invalid", "invalid_algo", "bafyTestCID", "txID123", PoWThreshold)
	if err != nil {
		t.Errorf("large file should skip PoW verification regardless of pow/alg values, got: %v", err)
	}
}

// ============================================================
// Verify 测试 — 小文件必须提供 PoW
// ============================================================

func TestVerify_SmallFileMissingPoW(t *testing.T) {
	err := Verify("", Algorithm, "bafyTestCID", "txID123", 1024)
	if err == nil {
		t.Fatal("expected error for missing PoW on small file")
	}
	if err != ErrMissingPoW {
		t.Errorf("expected ErrMissingPoW, got: %v", err)
	}
}

func TestVerify_SmallFileInvalidPoWFormat(t *testing.T) {
	err := Verify("not-a-number", Algorithm, "bafyTestCID", "txID123", 1024)
	if err == nil {
		t.Fatal("expected error for invalid PoW format")
	}
}

func TestVerify_SmallFileNegativePoW(t *testing.T) {
	err := Verify("-1", Algorithm, "bafyTestCID", "txID123", 1024)
	if err == nil {
		t.Fatal("expected error for negative PoW")
	}
}

// ============================================================
// Verify 测试 — 实际 PoW 验证
// ============================================================

// TestVerify_ValidPoW 使用预计算的 PoW 测试验证通过
// 测试向量需要预计算。使用 -pow 标志运行以生成测试向量。
// 在常规测试中跳过。
func TestVerify_ValidPoW(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping PoW computation test in short mode")
	}

	rootCID := "bafytest"
	dataTXID := "test123"
	dataSize := int64(1024) // 1 KiB，需要 PoW

	validPoW, err := ComputePoW(rootCID, dataTXID)
	if err != nil {
		t.Skipf("Could not compute test PoW vector: %v (this is expected in resource-constrained environments)", err)
		return
	}

	t.Logf("Found valid PoW salt: %s for rootCID=%s, dataTXID=%s", validPoW, rootCID, dataTXID)

	// 验证通过
	err = Verify(validPoW, Algorithm, rootCID, dataTXID, dataSize)
	if err != nil {
		t.Errorf("Valid PoW should pass verification, got: %v", err)
	}
}

// TestVerify_InvalidPoW_WrongSalt 使用错误的 salt 验证失败
func TestVerify_InvalidPoW_WrongSalt(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping PoW computation test in short mode")
	}

	rootCID := "bafytest"
	dataTXID := "test123"
	dataSize := int64(1024)

	validPoW, err := ComputePoW(rootCID, dataTXID)
	if err != nil {
		t.Skipf("Could not compute test PoW vector: %v", err)
		return
	}

	salt, _ := strconv.ParseUint(validPoW, 10, 64)
	wrongSalt := salt + 1
	wrongPoW := strconv.FormatUint(wrongSalt, 10)

	err = Verify(wrongPoW, Algorithm, rootCID, dataTXID, dataSize)
	if err == nil {
		t.Error("Wrong salt should fail PoW verification")
	}
}

// TestVerify_InvalidPoW_WrongRootCID 使用错误的 rootCID 验证失败
func TestVerify_InvalidPoW_WrongRootCID(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping PoW computation test in short mode")
	}

	rootCID := "bafytest"
	dataTXID := "test123"
	dataSize := int64(1024)

	validPoW, err := ComputePoW(rootCID, dataTXID)
	if err != nil {
		t.Skipf("Could not compute test PoW vector: %v", err)
		return
	}

	err = Verify(validPoW, Algorithm, "differentCID", dataTXID, dataSize)
	if err == nil {
		t.Error("Different rootCID should fail PoW verification")
	}
}

// TestVerify_InvalidPoW_WrongDataTXID 使用错误的 dataTXID 验证失败
func TestVerify_InvalidPoW_WrongDataTXID(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping PoW computation test in short mode")
	}

	rootCID := "bafytest"
	dataTXID := "test123"
	dataSize := int64(1024)

	validPoW, err := ComputePoW(rootCID, dataTXID)
	if err != nil {
		t.Skipf("Could not compute test PoW vector: %v", err)
		return
	}

	err = Verify(validPoW, Algorithm, rootCID, "differentTXID", dataSize)
	if err == nil {
		t.Error("Different dataTXID should fail PoW verification")
	}
}

// ============================================================
// Verify 测试 — 边界情况
// ============================================================

func TestVerify_ExactlyAtThreshold(t *testing.T) {
	// 正好 100 MiB：免 PoW
	err := Verify("", Algorithm, "bafyTestCID", "txID123", PoWThreshold)
	if err != nil {
		t.Errorf("File exactly at threshold should skip PoW, got: %v", err)
	}
}

func TestVerify_JustBelowThreshold(t *testing.T) {
	// 99.999 MiB：需要 PoW
	err := Verify("", Algorithm, "bafyTestCID", "txID123", PoWThreshold-1)
	if err == nil {
		t.Fatal("File just below threshold should require PoW")
	}
}

func TestVerify_ZeroByteFile(t *testing.T) {
	// 0 字节文件：需要 PoW
	err := Verify("", Algorithm, "bafyTestCID", "txID123", 0)
	if err == nil {
		t.Fatal("Zero-byte file should require PoW")
	}
}

// ============================================================
// hasLeadingZeroBytes 测试
// ============================================================

func TestHasLeadingZeroBytes(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		n        int
		expected bool
	}{
		{"exact match 2 zeros", []byte{0, 0, 1, 2}, 2, true},
		{"more zeros than required", []byte{0, 0, 0, 0}, 2, true},
		{"not enough zeros", []byte{0, 1, 0, 0}, 2, false},
		{"no zeros", []byte{1, 2, 3, 4}, 2, false},
		{"one zero needed, present", []byte{0, 1}, 1, true},
		{"one zero needed, absent", []byte{1, 0}, 1, false},
		{"empty data", []byte{}, 1, false},
		{"data shorter than n", []byte{0}, 2, false},
		{"zero n", []byte{1, 2}, 0, true},
		{"negative n edge case (loop doesn't execute)", []byte{1, 2}, -1, true}, // n <= 0: no check needed, vacuously true
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasLeadingZeroBytes(tt.data, tt.n)
			if result != tt.expected {
				t.Errorf("hasLeadingZeroBytes(%v, %d) = %v, want %v", tt.data, tt.n, result, tt.expected)
			}
		})
	}
}

// ============================================================
// ComputePoWParallel 测试
// ============================================================

// TestComputePoWParallel_Cancellation 验证 context 取消机制
func TestComputePoWParallel_Cancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := ComputePoWParallel(ctx, "test-cid", "test-tx", 4)
	if err != ErrPoWCancelled {
		t.Errorf("expected ErrPoWCancelled, got %v", err)
	}
}

// TestComputePoWParallel_NumWorkers1 验证 numWorkers=1 与单线程结果一致
func TestComputePoWParallel_NumWorkers1(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PoW computation in short mode")
	}

	rootCID := "test-consistency"
	dataTXID := "tx-consistency"

	saltSingle, err := ComputePoW(rootCID, dataTXID)
	if err != nil {
		t.Fatalf("ComputePoW failed: %v", err)
	}

	saltParallel, err := ComputePoWParallel(context.Background(), rootCID, dataTXID, 1)
	if err != nil {
		t.Fatalf("ComputePoWParallel(workers=1) failed: %v", err)
	}

	if saltSingle != saltParallel {
		t.Errorf("mismatch: single=%s, parallel(1)=%s", saltSingle, saltParallel)
	}

	t.Logf("Both single and parallel(1) found salt=%s", saltSingle)
}

// TestComputePoWParallel_Correctness 验证并行搜索结果满足难度要求
func TestComputePoWParallel_Correctness(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PoW computation in short mode")
	}

	rootCID := "parallel-correctness"
	dataTXID := "tx-correctness"

	salt, err := ComputePoWParallel(context.Background(), rootCID, dataTXID, 3)
	if err != nil {
		t.Fatalf("ComputePoWParallel failed: %v", err)
	}

	err = Verify(salt, Algorithm, rootCID, dataTXID, 1024)
	if err != nil {
		t.Errorf("salt %s does not satisfy PoW difficulty: %v", salt, err)
	}

	t.Logf("Parallel(3) found salt=%s, verified OK", salt)
}

// ============================================================
// 常量验证
// ============================================================

func TestConstants(t *testing.T) {
	if Algorithm != "argon2id-light-v1" {
		t.Error("Algorithm constant should be 'argon2id-light-v1'")
	}
	if MinLeadingZeroBytes != 2 {
		t.Error("MinLeadingZeroBytes should be 2")
	}
	if PoWThreshold != 100*1024*1024 {
		t.Error("PoWThreshold should be 100 MiB")
	}
}

// ============================================================
// 辅助函数
// ============================================================

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
