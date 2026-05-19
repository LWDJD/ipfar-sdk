// Package pow 快速 PoW 验证测试（仅用于功能验证）
//
// 本文件提供一套基于 SHA256 + 1 字节前导零的「快速 PoW」辅助函数，
// 用于在资源受限环境（如 1.6G 内存服务器）中验证 PoW 逻辑的正确性。
//
// 与正式 Argon2id 实现的区别：
//   - 哈希函数：SHA256（替代 Argon2id 20MB/1/1）
//   - 难度：1 字节前导零（替代 2 字节）
//   - 内存消耗：~几 KB（替代 20 MB）
//   - 单次验证耗时：~μs（替代 ~数十 ms）
//
// 本文件所有符号均为小写（包内私有），不会被外部导入。
// 正式实现的 Verify() / ComputePoW() 完全不受影响。
package pow

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strconv"
	"testing"
)

// ============================================================
// 快速 PoW 常量
// ============================================================

const (
	// fastAlgorithm 快速测试用算法标识
	fastAlgorithm = "sha256-fast-v1"
	// fastLeadingZeroBytes 快速测试前导零字节数（1 字节 = 平均 256 次计算）
	fastLeadingZeroBytes = 1
)

// ============================================================
// 快速 PoW 辅助函数
// ============================================================

// verifyFast 使用 SHA256 快速验证 PoW（仅测试用）
func verifyFast(pow, powAlg, rootCID, dataTXID string, dataSize int64) error {
	// 1. 大文件免 PoW（与正式逻辑一致）
	if dataSize >= PoWThreshold {
		return nil
	}

	// 2. 检查算法标识
	if powAlg == "" {
		return ErrMissingAlgorithm
	}
	if powAlg != fastAlgorithm {
		return fmt.Errorf("%w: expected %s, got %s", ErrAlgorithmMismatch, fastAlgorithm, powAlg)
	}

	// 3. 小文件必须提供 PoW
	if pow == "" {
		return ErrMissingPoW
	}

	// 4. 解析 salt
	salt, err := strconv.ParseUint(pow, 10, 64)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPoWFormat, err)
	}

	// 5. 构造输入
	password := []byte(rootCID + dataTXID)
	saltBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(saltBytes, salt)

	// 6. SHA256（替代 Argon2id）
	h := sha256.New()
	h.Write(password)
	h.Write(saltBytes)
	hash := h.Sum(nil)

	// 7. 检查前导零
	if !hasLeadingZeroBytes(hash, fastLeadingZeroBytes) {
		return ErrPoWVerificationFailed
	}

	return nil
}

// computePoWFast 使用 SHA256 快速计算满足难度的 PoW salt（仅测试用）
func computePoWFast(rootCID, dataTXID string) (string, error) {
	password := []byte(rootCID + dataTXID)

	for salt := uint64(0); salt < 10_000_000; salt++ {
		saltBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(saltBytes, salt)

		h := sha256.New()
		h.Write(password)
		h.Write(saltBytes)
		hash := h.Sum(nil)

		if hasLeadingZeroBytes(hash, fastLeadingZeroBytes) {
			return strconv.FormatUint(salt, 10), nil
		}
	}
	return "", fmt.Errorf("fast PoW exceeded safety limit (10M iterations)")
}

// ============================================================
// 测试用例：正确 PoW → 验证通过
// ============================================================

func TestFastPow_ValidPoW_Passes(t *testing.T) {
	rootCID := "bafyTestCID"
	dataTXID := "tx123"
	dataSize := int64(1024) // 1 KiB，需要 PoW

	// 快速计算一个有效 PoW（SHA256 极快）
	validPoW, err := computePoWFast(rootCID, dataTXID)
	if err != nil {
		t.Fatalf("Failed to compute fast PoW: %v", err)
	}
	t.Logf("Fast PoW salt found: %s for rootCID=%s dataTXID=%s", validPoW, rootCID, dataTXID)

	// 验证：正确 PoW 应通过
	err = verifyFast(validPoW, fastAlgorithm, rootCID, dataTXID, dataSize)
	if err != nil {
		t.Errorf("Valid PoW should pass verification, got: %v", err)
	}
}

// ============================================================
// 测试用例：错误 PoW → 验证不通过
// ============================================================

func TestFastPow_WrongPoW_Fails(t *testing.T) {
	rootCID := "bafyTestCID"
	dataTXID := "tx123"
	dataSize := int64(1024)

	// 计算正确 salt
	validPoW, err := computePoWFast(rootCID, dataTXID)
	if err != nil {
		t.Fatalf("Failed to compute fast PoW: %v", err)
	}

	// 用错误的 salt（正确 salt + 1）
	correctSalt, _ := strconv.ParseUint(validPoW, 10, 64)
	wrongPoW := strconv.FormatUint(correctSalt+1, 10)

	err = verifyFast(wrongPoW, fastAlgorithm, rootCID, dataTXID, dataSize)
	if err == nil {
		t.Error("Wrong salt should fail PoW verification")
	}
	t.Logf("Wrong salt correctly rejected: %v", err)

	// 测试错误的 rootCID
	err = verifyFast(validPoW, fastAlgorithm, "wrongCID", dataTXID, dataSize)
	if err == nil {
		t.Error("Wrong rootCID should fail PoW verification")
	}
	t.Logf("Wrong rootCID correctly rejected: %v", err)

	// 测试错误的 dataTXID
	err = verifyFast(validPoW, fastAlgorithm, rootCID, "wrongTXID", dataSize)
	if err == nil {
		t.Error("Wrong dataTXID should fail PoW verification")
	}
	t.Logf("Wrong dataTXID correctly rejected: %v", err)
}

// ============================================================
// 测试用例：大文件（≥100 MiB）→ 免 PoW，跳过验证
// ============================================================

func TestFastPow_LargeFile_SkipsVerification(t *testing.T) {
	// 即使 pow 为空、算法为空，大文件也应跳过
	tests := []struct {
		name     string
		pow      string
		powAlg   string
		dataSize int64
	}{
		{"exactly 100 MiB, empty fields", "", "", PoWThreshold},
		{"200 MiB, empty fields", "", "", 200 * 1024 * 1024},
		{"100 MiB, invalid pow/alg", "garbage", "garbage_algo", PoWThreshold},
		{"1 GiB, empty fields", "", "", 1024 * 1024 * 1024},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyFast(tt.pow, tt.powAlg, "bafyTestCID", "tx123", tt.dataSize)
			if err != nil {
				t.Errorf("Large file should skip PoW, got: %v", err)
			}
		})
	}
}

// ============================================================
// 测试用例：算法标识不匹配 → 拒绝
// ============================================================

func TestFastPow_AlgorithmMismatch_Rejected(t *testing.T) {
	rootCID := "bafyTestCID"
	dataTXID := "tx123"
	dataSize := int64(1024)

	validPoW, err := computePoWFast(rootCID, dataTXID)
	if err != nil {
		t.Fatalf("Failed to compute fast PoW: %v", err)
	}

	// 使用正式算法标识（argon2id-light-v1）而非快速算法标识
	err = verifyFast(validPoW, Algorithm, rootCID, dataTXID, dataSize)
	if err == nil {
		t.Error("Should reject when algorithm is 'argon2id-light-v1' but fast verify expects 'sha256-fast-v1'")
	}
	t.Logf("Algorithm mismatch correctly rejected: %v", err)

	// 空算法标识
	err = verifyFast(validPoW, "", rootCID, dataTXID, dataSize)
	if err == nil {
		t.Error("Should reject empty algorithm identifier")
	}
	t.Logf("Empty algorithm correctly rejected: %v", err)

	// 完全随机的算法标识
	err = verifyFast(validPoW, "random-algo-xyz", rootCID, dataTXID, dataSize)
	if err == nil {
		t.Error("Should reject unknown algorithm identifier")
	}
	t.Logf("Unknown algorithm correctly rejected: %v", err)
}

// ============================================================
// 测试用例：格式错误 / 缺少 PoW → 拒绝
// ============================================================

func TestFastPow_InvalidFormat_Rejected(t *testing.T) {
	dataSize := int64(1024)

	// 非数字 PoW
	err := verifyFast("not-a-number", fastAlgorithm, "cid", "tx", dataSize)
	if err == nil {
		t.Error("Should reject non-numeric PoW")
	}
	t.Logf("Non-numeric PoW rejected: %v", err)

	// 负数 PoW
	err = verifyFast("-1", fastAlgorithm, "cid", "tx", dataSize)
	if err == nil {
		t.Error("Should reject negative PoW")
	}
	t.Logf("Negative PoW rejected: %v", err)

	// 空 PoW（小文件）
	err = verifyFast("", fastAlgorithm, "cid", "tx", dataSize)
	if err == nil {
		t.Error("Should reject empty PoW for small file")
	}
	t.Logf("Empty PoW for small file rejected: %v", err)
}
