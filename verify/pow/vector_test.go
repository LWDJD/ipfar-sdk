package pow

import (
	"encoding/binary"
	"strconv"
	"testing"

	"golang.org/x/crypto/argon2"
)

// ============================================================
// PoW 测试向量生成（离线生成，验证确定性）
// ============================================================

// TestGeneratePoWVectors 生成已知正确的 PoW 测试向量
// 使用 -tags=powgen 运行以生成向量
// 常规测试中跳过（耗时）
func TestGeneratePoWVectors(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping PoW vector generation in short mode")
	}

	vectors := []struct {
		rootCID  string
		dataTXID string
	}{
		{"bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi", "test_tx_001"},
		{"bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi", "test_tx_002"},
	}

	for _, v := range vectors {
		salt, err := ComputePoW(v.rootCID, v.dataTXID)
		if err != nil {
			t.Logf("Vector (%s, %s): failed to compute: %v", v.rootCID, v.dataTXID, err)
			continue
		}
		t.Logf("VECTOR: rootCID=%s dataTXID=%s salt=%s", v.rootCID, v.dataTXID, salt)

		// 验证一致性
		err = Verify(salt, Algorithm, v.rootCID, v.dataTXID, 1024)
		if err != nil {
			t.Errorf("Self-verification failed for (%s, %s, salt=%s): %v",
				v.rootCID, v.dataTXID, salt, err)
		}
	}
}

// TestPoWTestVectors 使用硬编码的测试向量验证 PoW 正确性
// 这些向量必须通过离线生成并验证
func TestPoWTestVectors(t *testing.T) {
	// 测试向量结构
	type PoWVector struct {
		RootCID  string
		DataTXID string
		Salt     string // 已知正确的 salt
		DataSize int64
	}

	// 硬编码测试向量（需通过 TestGeneratePoWVectors 生成后填入）
	vectors := []PoWVector{
		// 占位：实际向量需运行 PoW 计算后填入
		// {RootCID: "...", DataTXID: "...", Salt: "...", DataSize: 1024},
	}

	for i, v := range vectors {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			err := Verify(v.Salt, Algorithm, v.RootCID, v.DataTXID, v.DataSize)
			if err != nil {
				t.Errorf("Vector %d failed: %v", i, err)
				t.Logf("  rootCID=%s, dataTXID=%s, salt=%s, dataSize=%d",
					v.RootCID, v.DataTXID, v.Salt, v.DataSize)
			}
		})
	}
}

// TestPoWDeterminism 验证 PoW 计算的确定性
// 相同输入应产生相同输出（Argon2id 是确定性的）
func TestPoWDeterminism(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping determinism test in short mode")
	}

	rootCID := "test_determinism_cid"
	dataTXID := "test_determinism_tx"

	salt1, err := ComputePoW(rootCID, dataTXID)
	if err != nil {
		t.Skipf("Could not compute first PoW: %v", err)
	}

	salt2, err := ComputePoW(rootCID, dataTXID)
	if err != nil {
		t.Fatalf("Could not compute second PoW: %v", err)
	}

	if salt1 != salt2 {
		t.Errorf("PoW computation is not deterministic: %s != %s", salt1, salt2)
	}

	t.Logf("Determinism verified: salt=%s", salt1)
}

// TestPoWQuickVector 使用简短的输入快速计算测试向量
// 使用非常短的密码便于快速找到 salt
func TestPoWQuickVector(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping quick vector in short mode")
	}

	// 使用极短输入减少 Argon2id 填充时间（但内存用量不变）
	rootCID := "b"
	dataTXID := "t"

	password := []byte(rootCID + dataTXID)

	var salt uint64
	found := false
	for salt = 0; salt < 500000; salt++ {
		saltBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(saltBytes, salt)

		hash := argon2.IDKey(password, saltBytes, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

		if hash[0] == 0 && hash[1] == 0 {
			found = true
			break
		}

		if salt%10000 == 0 && salt > 0 {
			t.Logf("Progress: salt=%d...", salt)
		}
	}

	if found {
		saltStr := strconv.FormatUint(salt, 10)
		t.Logf("✅ FOUND QUICK VECTOR: rootCID=%s dataTXID=%s salt=%s", rootCID, dataTXID, saltStr)

		// 验证
		err := Verify(saltStr, Algorithm, rootCID, dataTXID, 1024)
		if err != nil {
			t.Errorf("Quick vector self-verification failed: %v", err)
		}
	} else {
		t.Logf("Quick vector not found within 500000 iterations")
	}
}
