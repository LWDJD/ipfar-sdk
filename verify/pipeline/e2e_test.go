package pipeline

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"

	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"

	"github.com/LWDJD/ipfar-sdk/verify/ipfs"
	"github.com/LWDJD/ipfar-sdk/verify/metadata"
)

// ============================================================
// 端到端集成测试：元数据发现 → PoW → 元数据校验 → Index → Integrity
// ============================================================

// buildE2ECarV2 创建一个合成 CARv2 文件用于 e2e 测试
// 返回文件路径、根CID、索引条目
func buildE2ECarV2(t *testing.T) (string, cid.Cid, []ipfs.IndexEntry) {
	t.Helper()

	// 创建数据块
	block1Data := []byte("e2e test block 1 - hello IPFAR bridge")
	block2Data := []byte("e2e test block 2 - CAR v2 index verification")

	mh1, _ := multihash.Sum(block1Data, multihash.SHA2_256, -1)
	cid1 := cid.NewCidV1(cid.Raw, mh1)

	mh2, _ := multihash.Sum(block2Data, multihash.SHA2_256, -1)
	cid2 := cid.NewCidV1(cid.Raw, mh2)

	roots := []cid.Cid{cid1, cid2}

	// 构建 CARv1 数据段
	var carv1Data bytes.Buffer

	// CARv1 header
	carv1Header := buildE2ECarV1Header(roots)
	carv1Data.Write(carv1Header)

	// Block 1
	block1Section := buildE2ECarBlock(cid1, block1Data)
	block1Offset := uint64(4 + 48 + carv1Data.Len())
	carv1Data.Write(block1Section)

	// Block 2
	block2Section := buildE2ECarBlock(cid2, block2Data)
	block2Offset := uint64(4 + 48 + carv1Data.Len())
	carv1Data.Write(block2Section)

	// 构建索引
	indexEntries := []ipfs.IndexEntry{
		{CID: cid1, Offset: block1Offset},
		{CID: cid2, Offset: block2Offset},
	}

	indexBuilder := ipfs.NewIndexBuilder()
	for _, e := range indexEntries {
		indexBuilder.AddEntry(e.CID, e.Offset)
	}
	indexData := indexBuilder.Build()

	// 构建完整 CARv2 文件
	var carv2File bytes.Buffer

	// CARv2 pragma
	carv2File.Write([]byte{0x63, 0x61, 0x72, 0x02})

	// CARv2 header: Characteristics[16] + DataOffset[8] + DataSize[8] + IndexOffset[8] + IndexSize[8]
	v2Header := make([]byte, 48)
	binary.BigEndian.PutUint16(v2Header[8:10], 0x0402) // CID index
	binary.LittleEndian.PutUint64(v2Header[16:24], 52)  // CARv1 data at offset 52
	binary.LittleEndian.PutUint64(v2Header[24:32], uint64(carv1Data.Len()))
	binary.LittleEndian.PutUint64(v2Header[32:40], uint64(52+carv1Data.Len()))
	binary.LittleEndian.PutUint64(v2Header[40:48], uint64(len(indexData)))

	carv2File.Write(v2Header)
	carv2File.Write(carv1Data.Bytes())
	carv2File.Write(indexData)

	// 写入临时文件
	tmpFile, err := os.CreateTemp("", "e2e_carv2_*.car")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	if _, err := tmpFile.Write(carv2File.Bytes()); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tmpFile.Close()

	t.Cleanup(func() {
		os.Remove(tmpFile.Name())
	})

	return tmpFile.Name(), cid1, indexEntries
}

func buildE2ECarV1Header(roots []cid.Cid) []byte {
	var buf bytes.Buffer
	// version = 1 (varint)
	versionBuf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(versionBuf, 1)
	buf.Write(versionBuf[:n])
	// root count (varint)
	countBuf := make([]byte, binary.MaxVarintLen64)
	n = binary.PutUvarint(countBuf, uint64(len(roots)))
	buf.Write(countBuf[:n])
	for _, root := range roots {
		rootBytes := root.Bytes()
		lenBuf := make([]byte, binary.MaxVarintLen64)
		n = binary.PutUvarint(lenBuf, uint64(len(rootBytes)))
		buf.Write(lenBuf[:n])
		buf.Write(rootBytes)
	}
	return buf.Bytes()
}

func buildE2ECarBlock(c cid.Cid, data []byte) []byte {
	var buf bytes.Buffer
	cidBytes := c.Bytes()
	sectionLen := uint64(len(cidBytes) + len(data))
	lenBuf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(lenBuf, sectionLen)
	buf.Write(lenBuf[:n])
	buf.Write(cidBytes)
	buf.Write(data)
	return buf.Bytes()
}

// buildE2EMetadata 构建测试用元数据
func buildE2EMetadata(rootCID string) *metadata.Metadata {
	return &metadata.Metadata{
		Version:    1,
		Method:     "raw",
		RootCID:    rootCID,
		DataTXID:   "test_txid_1234567890123456789012345678901234567890",
		DataHeight: 1913000,
		DataSize:   200 * 1024 * 1024, // 200 MiB，免 PoW
	}
}

// ============================================================
// 安全预设档位 E2E 测试
// ============================================================

func TestE2E_AllPresets_NoCAR(t *testing.T) {
	meta := buildE2EMetadata("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")

	presets := []string{SecurityStrict, SecurityBalanced, SecurityLight, SecurityTrusted}

	for _, preset := range presets {
		t.Run(preset, func(t *testing.T) {
			p, err := NewPipelineWithPreset(preset)
			if err != nil {
				t.Fatalf("Failed to create pipeline for %s: %v", preset, err)
			}

			result := p.Verify(meta, false)

			// 所有预设对有效元数据（大文件免 PoW）应该通过
			if !result.Passed {
				t.Errorf("Preset %s: expected pass but got failure", preset)
				for _, r := range result.Results {
					t.Logf("  Step %s: passed=%v skipped=%v error=%s", r.Step, r.Passed, r.Skipped, r.Error)
				}
			}

			// 验证结果包含所有必要步骤
			stepMap := make(map[string]bool)
			for _, r := range result.Results {
				stepMap[r.Step] = true
			}
			for _, step := range []string{StepMetaValidate, StepPoW, StepIndex, StepReferenceChain, StepIntegrity} {
				if !stepMap[step] {
					t.Errorf("Preset %s: missing step %s", preset, step)
				}
			}
		})
	}
}

func TestE2E_AllPresets_WithCAR(t *testing.T) {
	carPath, rootCID, _ := buildE2ECarV2(t)
	meta := buildE2EMetadata(rootCID.String())

	presets := []string{SecurityStrict, SecurityBalanced, SecurityLight, SecurityTrusted}

	for _, preset := range presets {
		t.Run(preset, func(t *testing.T) {
			p, err := NewPipelineWithPreset(preset)
			if err != nil {
				t.Fatalf("Failed to create pipeline for %s: %v", preset, err)
			}

			// 注入基于 CAR 文件的验证器
			p.SetCarFile(carPath)
			// 覆盖 PoW 为大文件跳过（免 PoW）
			p.SetPoWVerifier(func(powStr, powAlg, rootCID, dataTXID string, dataSize int64) error {
				return nil // 大文件免 PoW
			})

			result := p.Verify(meta, true)

			t.Logf("Preset %s: passed=%v", preset, result.Passed)
			for _, r := range result.Results {
				t.Logf("  Step %s: passed=%v skipped=%v error=%s message=%s",
					r.Step, r.Passed, r.Skipped, r.Error, r.Message)
			}

			// 验证 Index 步骤的行为取决于预设
			foundIndex := false
			for _, r := range result.Results {
				if r.Step == StepIndex {
					foundIndex = true
					config := PresetConfigs[preset]
					if config.VerifyIndex {
						if r.Skipped {
							t.Errorf("Preset %s: Index should not be skipped when enabled", preset)
						}
						if !r.Passed {
							t.Errorf("Preset %s: Index should pass for valid CAR file: %s", preset, r.Error)
						}
					} else {
						if !r.Skipped {
							t.Errorf("Preset %s: Index should be skipped when disabled", preset)
						}
					}
				}
			}
			if !foundIndex {
				t.Errorf("Preset %s: Index step not found in results", preset)
			}
		})
	}
}

// ============================================================
// 完整流程测试：元数据发现 → PoW 验证 → 元数据校验 → Index → Integrity
// ============================================================

func TestE2E_FullPipeline_Strict(t *testing.T) {
	carPath, rootCID, _ := buildE2ECarV2(t)
	meta := buildE2EMetadata(rootCID.String())

	// 模拟完整流程：
	// 1. 从 Arweave 发现元数据（这里直接构建）
	// 2. 验证元数据合法性
	// 3. 检查是否需要 PoW（大文件免 PoW）
	// 4. 下载 CAR 文件
	// 5. 验证 CAR v2 Index
	// 6. 验证引用链（无引用）
	// 7. 验证数据完整性

	p := NewPipeline(PresetConfigs[SecurityStrict])
	p.SetCarFile(carPath)
	p.SetPoWVerifier(func(powStr, powAlg, rootCID, dataTXID string, dataSize int64) error {
		return nil // 大文件免 PoW
	})

	result := p.Verify(meta, true)

	if !result.Passed {
		t.Fatal("Full pipeline strict mode should pass")
	}

	// 验证所有步骤
	expectedSteps := map[string]bool{
		StepMetaValidate:   false,
		StepPoW:            false,
		StepIndex:          false,
		StepReferenceChain: false,
		StepIntegrity:      false,
	}

	for _, r := range result.Results {
		if _, ok := expectedSteps[r.Step]; ok {
			expectedSteps[r.Step] = true
		}
		if !r.Passed && !r.Skipped {
			t.Errorf("Step %s failed: %s", r.Step, r.Error)
		}
	}

	for step, found := range expectedSteps {
		if !found {
			t.Errorf("Missing step: %s", step)
		}
	}

	t.Log("✅ Full pipeline strict mode passed with all steps executed")
}

func TestE2E_FullPipeline_Balanced(t *testing.T) {
	carPath, rootCID, _ := buildE2ECarV2(t)
	meta := buildE2EMetadata(rootCID.String())

	p := NewPipeline(PresetConfigs[SecurityBalanced])
	p.SetCarFile(carPath)
	p.SetPoWVerifier(func(powStr, powAlg, rootCID, dataTXID string, dataSize int64) error {
		return nil
	})

	result := p.Verify(meta, true)

	if !result.Passed {
		t.Fatal("Full pipeline balanced mode should pass")
	}

	// Balanced: PoW=on, Index=on, ReferenceChain=off, Integrity=on
	for _, r := range result.Results {
		switch r.Step {
		case StepReferenceChain:
			if !r.Skipped {
				t.Error("ReferenceChain should be skipped in balanced mode")
			}
		case StepIndex:
			if r.Skipped {
				t.Error("Index should not be skipped in balanced mode")
			}
		}
	}

	t.Log("✅ Full pipeline balanced mode passed")
}

func TestE2E_FullPipeline_Light(t *testing.T) {
	carPath, rootCID, _ := buildE2ECarV2(t)
	meta := buildE2EMetadata(rootCID.String())

	p := NewPipeline(PresetConfigs[SecurityLight])
	p.SetCarFile(carPath)
	p.SetPoWVerifier(func(powStr, powAlg, rootCID, dataTXID string, dataSize int64) error {
		return nil
	})

	result := p.Verify(meta, true)

	if !result.Passed {
		t.Fatal("Full pipeline light mode should pass")
	}

	// Light: PoW=on, Index=off, ReferenceChain=on, Integrity=off
	// (Index existence is always enforced via StepIndexExistence, non-configurable)
	for _, r := range result.Results {
		switch r.Step {
		case StepIndexExistence:
			if r.Skipped {
				t.Error("Index existence should NOT be skipped — always enforced by spec §3.4")
			}
		case StepIndex:
			if !r.Skipped {
				t.Error("Index content verification should be skipped in light mode")
			}
		case StepIntegrity:
			if !r.Skipped {
				t.Error("Integrity should be skipped in light mode")
			}
		case StepReferenceChain:
			if r.Skipped && r.Message != "verification disabled by config" {
				// reference chain might be skipped due to no references, that's ok too
			}
		}
	}

	t.Log("✅ Full pipeline light mode passed")
}

func TestE2E_FullPipeline_Trusted(t *testing.T) {
	meta := buildE2EMetadata("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")

	p := NewPipeline(PresetConfigs[SecurityTrusted])
	result := p.Verify(meta, false)

	if !result.Passed {
		t.Fatal("Full pipeline trusted mode should pass")
	}

	// Trusted: all optional verification off
	for _, r := range result.Results {
		if r.Step != StepMetaValidate {
			if !r.Skipped {
				t.Errorf("Step %s should be skipped in trusted mode", r.Step)
			}
		}
	}

	t.Log("✅ Full pipeline trusted mode passed")
}

// ============================================================
// 元数据校验 + PoW 集成测试
// ============================================================

func TestE2E_MetadataWithPoW(t *testing.T) {
	// 小文件需要 PoW
	meta := buildE2EMetadata("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")
	meta.DataSize = 50 * 1024 * 1024 // 50 MiB，需要 PoW
	meta.PoW = "42"                   // 假设这是有效 PoW
	meta.PoWAlg = "argon2id-light-v1"

	p := NewPipeline(PresetConfigs[SecurityStrict])
	p.SetPoWVerifier(func(powStr, powAlg, rootCID, dataTXID string, dataSize int64) error {
		// 模拟：验证通过
		if powStr != "42" {
			t.Error("Expected PoW value '42'")
		}
		if powAlg != "argon2id-light-v1" {
			t.Error("Expected PoW algorithm 'argon2id-light-v1'")
		}
		return nil
	})

	result := p.Verify(meta, false)

	if !result.Passed {
		t.Error("Metadata with valid PoW should pass")
	}

	// PoW 步骤不应该被跳过（小文件）
	for _, r := range result.Results {
		if r.Step == StepPoW {
			if r.Skipped {
				t.Error("PoW should not be skipped for small file")
			}
		}
	}

	t.Log("✅ Metadata + PoW integration passed")
}

func TestE2E_MetadataMissingPoW(t *testing.T) {
	meta := buildE2EMetadata("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")
	meta.DataSize = 50 * 1024 * 1024 // 50 MiB
	meta.PoW = ""                     // 缺少 PoW
	meta.PoWAlg = ""

	// 元数据自身校验会失败（缺少 PoW）
	err := meta.Validate()
	if err == nil {
		t.Fatal("Metadata should fail validation without PoW for small file")
	}
	t.Logf("Correctly detected missing PoW: %v", err)

	// Pipeline 也会失败（元数据校验失败）
	p := NewPipeline(PresetConfigs[SecurityStrict])
	result := p.Verify(meta, false)
	if result.Passed {
		t.Error("Pipeline should fail for metadata missing PoW")
	}
}

// ============================================================
// CAR v2 Index 内容完整性验证集成测试
// ============================================================

func TestE2E_IndexVerification_Valid(t *testing.T) {
	carPath, rootCID, _ := buildE2ECarV2(t)
	meta := buildE2EMetadata(rootCID.String())

	p := NewPipeline(PresetConfigs[SecurityStrict])
	p.SetCarFile(carPath)
	p.SetPoWVerifier(func(powStr, powAlg, rootCID, dataTXID string, dataSize int64) error {
		return nil
	})

	result := p.Verify(meta, true)

	if !result.Passed {
		t.Fatal("Index verification should pass for valid CARv2 file")
	}

	// 确认 Index 步骤通过
	for _, r := range result.Results {
		if r.Step == StepIndex {
			if !r.Passed || r.Skipped {
				t.Errorf("Index step: passed=%v skipped=%v error=%s", r.Passed, r.Skipped, r.Error)
			}
		}
	}

	t.Log("✅ Index verification integration passed")
}

func TestE2E_IndexVerification_Disabled(t *testing.T) {
	carPath, rootCID, _ := buildE2ECarV2(t)
	meta := buildE2EMetadata(rootCID.String())

	// 关闭 Index 验证
	config := VerifyConfig{
		VerifyPoW:            false,
		VerifyIndex:          false,
		VerifyReferenceChain: false,
		VerifyIntegrity:      false,
	}

	p := NewPipeline(config)
	p.SetCarFile(carPath)

	result := p.Verify(meta, true)

	// Index 应该被跳过
	for _, r := range result.Results {
		if r.Step == StepIndex {
			if !r.Skipped {
				t.Error("Index should be skipped when disabled")
			}
		}
	}

	t.Log("✅ Index verification disabled correctly skips")
}

// ============================================================
// 数据完整性验证集成测试
// ============================================================

func TestE2E_IntegrityVerification(t *testing.T) {
	carPath, rootCID, _ := buildE2ECarV2(t)
	meta := buildE2EMetadata(rootCID.String())

	p := NewPipeline(PresetConfigs[SecurityStrict])
	p.SetCarFile(carPath)
	p.SetPoWVerifier(func(powStr, powAlg, rootCID, dataTXID string, dataSize int64) error {
		return nil
	})

	result := p.Verify(meta, true)

	if !result.Passed {
		t.Fatal("Integrity verification should pass for valid CARv2 file")
	}

	// 确认 Integrity 步骤通过
	for _, r := range result.Results {
		if r.Step == StepIntegrity {
			if !r.Passed || r.Skipped {
				t.Errorf("Integrity step: passed=%v skipped=%v error=%s", r.Passed, r.Skipped, r.Error)
			}
		}
	}

	t.Log("✅ Integrity verification integration passed")
}

// ============================================================
// 引用链验证集成测试
// ============================================================

func TestE2E_ReferenceChain_WithReference(t *testing.T) {
	meta := buildE2EMetadata("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")
	ref := metadata.ReferenceMap{
		"chunk_tx_1_1234567890123456789012345678901234567890": {
			Height: 1913001,
			CIDs:   []string{"bafySharedCID1"},
		},
	}
	meta.Reference = &ref
	meta.DataSize = 200 * 1024 * 1024 // 大文件免 PoW

	callCount := 0
	p := NewPipeline(PresetConfigs[SecurityStrict])
	p.SetPoWVerifier(func(powStr, powAlg, rootCID, dataTXID string, dataSize int64) error {
		return nil
	})
	p.SetIndexVerifier(func() error { return nil })
	p.SetReferenceVerifier(func(m *metadata.Metadata) error {
		callCount++
		if !m.HasReference() {
			t.Error("Expected HasReference to be true")
		}
		if len(*m.Reference) != 1 {
			t.Errorf("Expected 1 reference, got %d", len(*m.Reference))
		}
		return nil
	})
	p.SetIntegrityVerifier(func() error { return nil })

	result := p.Verify(meta, true)

	if !result.Passed {
		t.Error("Reference chain verification should pass")
	}
	if callCount != 1 {
		t.Errorf("Reference verifier should be called once, got %d", callCount)
	}

	t.Log("✅ Reference chain integration passed")
}

// ============================================================
// 错误传播测试
// ============================================================

func TestE2E_ErrorPropagation(t *testing.T) {
	meta := buildE2EMetadata("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")
	// 小文件需要 PoW
	meta.DataSize = 1024
	meta.PoW = "dummy"
	meta.PoWAlg = "argon2id-light-v1"

	p := NewPipeline(PresetConfigs[SecurityStrict])
	p.SetMetaValidator(func(m *metadata.Metadata) error {
		return nil // 元数据通过
	})
	p.SetPoWVerifier(func(powStr, powAlg, rootCID, dataTXID string, dataSize int64) error {
		return ErrPoWVerificationFailed
	})
	p.SetIndexVerifier(func() error { return nil })
	p.SetReferenceVerifier(func(m *metadata.Metadata) error { return nil })
	p.SetIntegrityVerifier(func() error { return nil })

	result := p.Verify(meta, true)

	if result.Passed {
		t.Fatal("Error propagation should cause pipeline failure")
	}

	// PoW 失败应该在结果中体现
	foundPoWFail := false
	for _, r := range result.Results {
		if r.Step == StepPoW && !r.Passed {
			foundPoWFail = true
			if r.Error == "" {
				t.Error("PoW failure should include error message")
			}
		}
	}
	if !foundPoWFail {
		t.Error("PoW failure not found in results")
	}

	t.Log("✅ Error propagation works correctly")
}

// ============================================================
// SetCarFile 测试
// ============================================================

func TestE2E_SetCarFile(t *testing.T) {
	carPath, rootCID, _ := buildE2ECarV2(t)
	meta := buildE2EMetadata(rootCID.String())

	p := NewPipeline(PresetConfigs[SecurityStrict])
	p.SetCarFile(carPath)

	// PoW 需要覆盖，因为大文件默认走免 PoW 但我们的默认 verifier 会实际计算
	p.SetPoWVerifier(func(powStr, powAlg, rootCID, dataTXID string, dataSize int64) error {
		return nil
	})

	result := p.Verify(meta, true)

	if !result.Passed {
		t.Fatal("SetCarFile-based pipeline should pass")
	}

	// 验证 Index 步骤执行了实际验证
	indexFound := false
	for _, r := range result.Results {
		if r.Step == StepIndex {
			indexFound = true
			if !r.Passed {
				t.Errorf("Index verification failed: %s", r.Error)
			}
		}
	}
	if !indexFound {
		t.Error("Index step not found")
	}

	t.Log("✅ SetCarFile integration passed")
}

// ============================================================
// 边界情况测试
// ============================================================

func TestE2E_NonExistentCarFile(t *testing.T) {
	meta := buildE2EMetadata("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")

	p := NewPipeline(PresetConfigs[SecurityStrict])
	p.SetCarFile("/nonexistent/car/file.car")
	p.SetPoWVerifier(func(powStr, powAlg, rootCID, dataTXID string, dataSize int64) error {
		return nil
	})

	result := p.Verify(meta, true)

	// Index 和 Integrity 应该失败（文件不存在）
	for _, r := range result.Results {
		if r.Step == StepIndex || r.Step == StepIntegrity {
			if r.Passed && !r.Skipped {
				t.Errorf("%s should fail for non-existent file", r.Step)
			}
		}
	}

	t.Log("✅ Non-existent CAR file handled correctly")
}

func TestE2E_EmptyMetadata(t *testing.T) {
	p := NewPipeline(PresetConfigs[SecurityStrict])
	result := p.Verify(&metadata.Metadata{}, false)

	if result.Passed {
		t.Fatal("Empty metadata should fail")
	}

	t.Log("✅ Empty metadata correctly rejected")
}
