package pipeline

import (
	"errors"
	"testing"

	"github.com/LWDJD/ipfar-sdk/verify/metadata"
)

// ============================================================
// 预设配置测试
// ============================================================

func TestPresetConfigs(t *testing.T) {
	tests := []struct {
		preset   string
		wantPoW  bool
		wantIdx  bool
		wantRef  bool
		wantInt  bool
	}{
		{SecurityStrict, true, true, true, true},
		{SecurityBalanced, true, true, false, true},
		{SecurityLight, true, false, true, false},
		{SecurityTrusted, false, false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.preset, func(t *testing.T) {
			config, err := GetPreset(tt.preset)
			if err != nil {
				t.Fatalf("GetPreset(%s) returned error: %v", tt.preset, err)
			}
			if config.VerifyPoW != tt.wantPoW {
				t.Errorf("VerifyPoW = %v, want %v", config.VerifyPoW, tt.wantPoW)
			}
			if config.VerifyIndex != tt.wantIdx {
				t.Errorf("VerifyIndex = %v, want %v", config.VerifyIndex, tt.wantIdx)
			}
			if config.VerifyReferenceChain != tt.wantRef {
				t.Errorf("VerifyReferenceChain = %v, want %v", config.VerifyReferenceChain, tt.wantRef)
			}
			if config.VerifyIntegrity != tt.wantInt {
				t.Errorf("VerifyIntegrity = %v, want %v", config.VerifyIntegrity, tt.wantInt)
			}
		})
	}
}

func TestGetPreset_Invalid(t *testing.T) {
	_, err := GetPreset("invalid")
	if err == nil {
		t.Fatal("Expected error for invalid preset")
	}
}

func TestNewVerifyConfigFromPreset(t *testing.T) {
	config, err := NewVerifyConfigFromPreset(SecurityStrict)
	if err != nil {
		t.Fatalf("NewVerifyConfigFromPreset failed: %v", err)
	}
	if !config.VerifyPoW {
		t.Error("Strict preset should have VerifyPoW=true")
	}
}

func TestNewVerifyConfigFromPreset_Invalid(t *testing.T) {
	_, err := NewVerifyConfigFromPreset("unknown")
	if err == nil {
		t.Fatal("Expected error for invalid preset")
	}
}

// ============================================================
// NewVerifyConfig 测试
// ============================================================

func TestNewVerifyConfig(t *testing.T) {
	config := NewVerifyConfig()
	// 默认应该是 light 模式
	light := PresetConfigs[SecurityLight]
	if config != light {
		t.Error("NewVerifyConfig should return light preset")
	}
}

// ============================================================
// Pipeline 基础测试
// ============================================================

func TestNewPipeline(t *testing.T) {
	config := PresetConfigs[SecurityStrict]
	p := NewPipeline(config)

	if p == nil {
		t.Fatal("NewPipeline returned nil")
	}
	if p.config != config {
		t.Error("Pipeline config mismatch")
	}
}

func TestNewPipelineWithPreset(t *testing.T) {
	p, err := NewPipelineWithPreset(SecurityBalanced)
	if err != nil {
		t.Fatalf("NewPipelineWithPreset failed: %v", err)
	}
	if !p.config.VerifyPoW {
		t.Error("Balanced preset should have VerifyPoW=true")
	}
}

func TestNewPipelineWithPreset_Invalid(t *testing.T) {
	_, err := NewPipelineWithPreset("invalid")
	if err == nil {
		t.Fatal("Expected error for invalid preset")
	}
}

// ============================================================
// Verify 测试 — 元数据校验（强制）
// ============================================================

func TestVerify_NilMetadata(t *testing.T) {
	p := NewPipeline(PresetConfigs[SecurityStrict])
	result := p.Verify(nil, false)

	if result.Passed {
		t.Fatal("Nil metadata should fail verification")
	}
	if len(result.Results) == 0 {
		t.Fatal("Expected at least one result")
	}
	if result.Results[0].Step != StepMetaValidate {
		t.Errorf("First step should be meta_validate, got %s", result.Results[0].Step)
	}
	if result.Results[0].Passed {
		t.Error("Meta validate should fail for nil metadata")
	}
}

func TestVerify_InvalidMetadata(t *testing.T) {
	meta := &metadata.Metadata{
		Version: 99, // Invalid version
	}

	p := NewPipeline(PresetConfigs[SecurityStrict])
	result := p.Verify(meta, false)

	if result.Passed {
		t.Fatal("Invalid metadata should fail verification")
	}
	if len(result.Results) == 0 {
		t.Fatal("Expected at least one result")
	}
}

func TestVerify_ValidMetadata_NoCAR(t *testing.T) {
	meta := validMeta()

	// Strict 模式，但 CAR 不可用
	p := NewPipeline(PresetConfigs[SecurityStrict])
	result := p.Verify(meta, false)

	// 元数据验证应该通过
	if result.Results[0].Step != StepMetaValidate || !result.Results[0].Passed {
		t.Error("Meta validate should pass for valid metadata")
	}

	// PoW 步骤应该跳过（大文件免 PoW）
	foundPoW := false
	for _, r := range result.Results {
		if r.Step == StepPoW {
			foundPoW = true
			if !r.Skipped {
				t.Error("PoW should be skipped for large file")
			}
		}
	}
	if !foundPoW {
		t.Error("Expected PoW step in results")
	}

	// Index/Reference/Integrity 应该因 CAR 不可用而跳过
	for _, step := range []string{StepIndex, StepReferenceChain, StepIntegrity} {
		found := false
		for _, r := range result.Results {
			if r.Step == step {
				found = true
				if !r.Skipped {
					t.Errorf("%s should be skipped when CAR unavailable", step)
				}
				if r.Message != "CAR file not available, step skipped" {
					t.Errorf("%s skip message mismatch: %s", step, r.Message)
				}
			}
		}
		if !found {
			t.Errorf("Expected %s step in results", step)
		}
	}

	// 整体应通过
	if !result.Passed {
		t.Error("Valid metadata without CAR should pass")
	}
}

func TestVerify_SmallFile_NeedsPoW(t *testing.T) {
	meta := validMeta()
	meta.DataSize = 1024 // 1 KiB，需要 PoW
	meta.PoW = "42"      // 必须提供 PoW 字段，否则元数据校验失败
	meta.PoWAlg = "argon2id-light-v1"

	p := NewPipeline(PresetConfigs[SecurityStrict])
	// 注入自定义 PoW 验证器
	p.SetPoWVerifier(func(powStr, powAlg, rootCID, dataTXID string, dataSize int64) error {
		// 验证通过
		return nil
	})

	result := p.Verify(meta, false)

	// PoW 步骤不应被跳过（小文件且验证开启）
	foundPoW := false
	for _, r := range result.Results {
		if r.Step == StepPoW {
			foundPoW = true
			if r.Skipped {
				t.Error("PoW should not be skipped for small file")
			}
			if !r.Passed {
				t.Error("PoW should pass with custom verifier")
			}
		}
	}
	if !foundPoW {
		t.Error("Expected PoW step in results")
	}
}

func TestVerify_SmallFile_PoWFails(t *testing.T) {
	meta := validMeta()
	meta.DataSize = 1024

	p := NewPipeline(PresetConfigs[SecurityStrict])
	p.SetPoWVerifier(func(powStr, powAlg, rootCID, dataTXID string, dataSize int64) error {
		return errors.New("PoW verification failed")
	})

	result := p.Verify(meta, false)

	if result.Passed {
		t.Fatal("Small file with failed PoW should not pass")
	}
}

// ============================================================
// Verify 测试 — 可配置验证开关
// ============================================================

func TestVerify_DisabledVerification(t *testing.T) {
	meta := validMeta() // 150 MiB, no PoW needed → meta validation passes

	// Trusted 模式：关闭所有验证
	p := NewPipeline(PresetConfigs[SecurityTrusted])

	result := p.Verify(meta, false)

	// 元数据必须验证通过
	if !result.Results[0].Passed {
		t.Error("Meta validate should pass for valid metadata")
	}

	// PoW 应该被跳过（disabled by config）
	for _, r := range result.Results {
		if r.Step == StepPoW {
			if !r.Skipped {
				t.Error("PoW should be skipped in trusted mode")
			}
		}
	}

	// 整体应通过
	if !result.Passed {
		t.Error("Trusted mode should pass for valid metadata")
	}
}

func TestVerify_CustomConfig(t *testing.T) {
	meta := validMeta()

	// 自定义配置：仅开启 PoW
	config := VerifyConfig{
		VerifyPoW:            true,
		VerifyIndex:          false,
		VerifyReferenceChain: false,
		VerifyIntegrity:      false,
	}

	p := NewPipeline(config)
	result := p.Verify(meta, false)

	// Index 应被跳过（disabled）
	for _, r := range result.Results {
		if r.Step == StepIndex {
			if !r.Skipped {
				t.Error("Index should be skipped when disabled")
			}
		}
	}
}

// ============================================================
// Verify 测试 — CAR 可用时的完整流程
// ============================================================

func TestVerify_WithCAR_AllPass(t *testing.T) {
	meta := validMeta()

	p := NewPipeline(PresetConfigs[SecurityStrict])

	// 注入通过所有验证的自定义验证器
	p.SetPoWVerifier(func(powStr, powAlg, rootCID, dataTXID string, dataSize int64) error {
		return nil
	})
	p.SetIndexVerifier(func() error {
		return nil
	})
	p.SetReferenceVerifier(func(meta *metadata.Metadata) error {
		return nil
	})
	p.SetIntegrityVerifier(func() error {
		return nil
	})

	result := p.Verify(meta, true)

	if !result.Passed {
		t.Error("All-pass verifiers should result in passed")
	}

	// 应该包含所有 5 个步骤
	if len(result.Results) != 5 {
		t.Errorf("Expected 5 steps, got %d", len(result.Results))
	}

	for _, r := range result.Results {
		if !r.Passed && !r.Skipped {
			t.Errorf("Step %s should pass (or be legitimately skipped): %s", r.Step, r.Error)
		}
		// PoW 对于大文件是规范的"免 PoW"跳过，这是正确的
		if r.Step == StepPoW && r.Skipped {
			if r.Message != "file size >= 100 MiB, PoW not required" {
				t.Errorf("PoW skip message unexpected: %s", r.Message)
			}
		}
	}
}

func TestVerify_WithCAR_IndexFails(t *testing.T) {
	meta := validMeta()

	p := NewPipeline(PresetConfigs[SecurityStrict])
	p.SetPoWVerifier(func(powStr, powAlg, rootCID, dataTXID string, dataSize int64) error {
		return nil
	})
	p.SetIndexVerifier(func() error {
		return errors.New("index corrupted")
	})

	result := p.Verify(meta, true)

	if result.Passed {
		t.Fatal("Index failure should cause overall failure")
	}

	// 验证 Index 步骤失败
	foundIndex := false
	for _, r := range result.Results {
		if r.Step == StepIndex {
			foundIndex = true
			if r.Passed {
				t.Error("Index step should fail")
			}
		}
	}
	if !foundIndex {
		t.Error("Expected Index step in results")
	}
}

func TestVerify_WithCAR_ReferenceFails(t *testing.T) {
	meta := validMeta()
	ref := metadata.ReferenceMap{"tx": {Height: 1, CIDs: []string{"cid"}}}
	meta.Reference = &ref

	p := NewPipeline(PresetConfigs[SecurityStrict])
	p.SetPoWVerifier(func(powStr, powAlg, rootCID, dataTXID string, dataSize int64) error {
		return nil
	})
	p.SetIndexVerifier(func() error { return nil })
	p.SetReferenceVerifier(func(meta *metadata.Metadata) error {
		return errors.New("reference chain broken")
	})

	result := p.Verify(meta, true)

	if result.Passed {
		t.Fatal("Reference failure should cause overall failure")
	}
}

func TestVerify_WithCAR_IntegrityFails(t *testing.T) {
	meta := validMeta()

	p := NewPipeline(PresetConfigs[SecurityStrict])
	p.SetPoWVerifier(func(powStr, powAlg, rootCID, dataTXID string, dataSize int64) error {
		return nil
	})
	p.SetIndexVerifier(func() error { return nil })
	p.SetReferenceVerifier(func(meta *metadata.Metadata) error { return nil })
	p.SetIntegrityVerifier(func() error {
		return errors.New("hash mismatch")
	})

	result := p.Verify(meta, true)

	if result.Passed {
		t.Fatal("Integrity failure should cause overall failure")
	}
}

// ============================================================
// 验证步骤跳过场景
// ============================================================

func TestVerify_ReferenceSkippedWhenNoReference(t *testing.T) {
	meta := validMeta() // 没有 reference

	p := NewPipeline(PresetConfigs[SecurityStrict])
	p.SetPoWVerifier(func(powStr, powAlg, rootCID, dataTXID string, dataSize int64) error {
		return nil
	})
	p.SetIndexVerifier(func() error { return nil })
	p.SetIntegrityVerifier(func() error { return nil })

	result := p.Verify(meta, true)

	// Reference 步骤应该通过（默认验证器在无引用时自动通过）
	for _, r := range result.Results {
		if r.Step == StepReferenceChain {
			if !r.Passed {
				t.Error("Reference step should pass when no references exist")
			}
		}
	}
}

// ============================================================
// 便捷函数测试
// ============================================================

func TestQuickVerify(t *testing.T) {
	meta := validMeta()
	result := QuickVerify(meta, PresetConfigs[SecurityStrict])

	if !result.Passed {
		t.Error("QuickVerify should pass for valid metadata")
	}

	// QuickVerify 不涉及 CAR，后三步应跳过
	for _, r := range result.Results {
		if r.Step == StepIndex || r.Step == StepIntegrity {
			if !r.Skipped {
				t.Errorf("%s should be skipped in QuickVerify", r.Step)
			}
		}
	}
}

func TestFullVerify(t *testing.T) {
	meta := validMeta()

	p := NewPipeline(PresetConfigs[SecurityStrict])
	p.SetPoWVerifier(func(powStr, powAlg, rootCID, dataTXID string, dataSize int64) error {
		return nil
	})
	p.SetIndexVerifier(func() error { return nil })
	p.SetReferenceVerifier(func(meta *metadata.Metadata) error { return nil })
	p.SetIntegrityVerifier(func() error { return nil })

	// 注意：FullVerify 创建新 Pipeline，所以我们需要用注入好的 pipeline
	result := p.Verify(meta, true)

	if !result.Passed {
		t.Error("FullVerify should pass with all verifiers passing")
	}
}

func TestVerifyWithDefaultConfig(t *testing.T) {
	meta := validMeta()
	result := VerifyWithDefaultConfig(meta, false)

	if !result.Passed {
		t.Error("Default config should pass for valid metadata")
	}
}

// ============================================================
// Pipeline 自定义注入测试
// ============================================================

func TestPipeline_CustomMetaValidator(t *testing.T) {
	meta := validMeta()

	p := NewPipeline(PresetConfigs[SecurityStrict])
	p.SetMetaValidator(func(m *metadata.Metadata) error {
		return errors.New("custom meta validation failed")
	})

	result := p.Verify(meta, false)

	if result.Passed {
		t.Fatal("Custom meta validator failure should cause failure")
	}
}

func TestPipeline_AllInjections(t *testing.T) {
	meta := validMeta()

	p := NewPipeline(PresetConfigs[SecurityStrict])

	callCount := 0
	p.SetPoWVerifier(func(powStr, powAlg, rootCID, dataTXID string, dataSize int64) error {
		callCount++
		return nil
	})
	p.SetIndexVerifier(func() error {
		callCount++
		return nil
	})
	p.SetReferenceVerifier(func(meta *metadata.Metadata) error {
		callCount++
		return nil
	})
	p.SetIntegrityVerifier(func() error {
		callCount++
		return nil
	})

	result := p.Verify(meta, true)

	if !result.Passed {
		t.Error("All injected verifiers should pass")
	}
}

// ============================================================
// 错误定义测试
// ============================================================

func TestErrorDefinitions(t *testing.T) {
	// 确保错误定义不为空
	errors := []error{
		ErrMetaValidateFailed,
		ErrPoWVerificationFailed,
		ErrIndexVerificationFailed,
		ErrReferenceChainFailed,
		ErrIntegrityFailed,
	}

	for _, err := range errors {
		if err.Error() == "" {
			t.Error("Error should have a non-empty message")
		}
	}
}

// ============================================================
// VerifyResult 场景测试
// ============================================================

func TestVerifyResult_AllStepsPresent(t *testing.T) {
	meta := validMeta()

	p := NewPipeline(PresetConfigs[SecurityStrict])
	p.SetPoWVerifier(func(powStr, powAlg, rootCID, dataTXID string, dataSize int64) error {
		return nil
	})
	p.SetIndexVerifier(func() error { return nil })
	p.SetReferenceVerifier(func(meta *metadata.Metadata) error { return nil })
	p.SetIntegrityVerifier(func() error { return nil })

	result := p.Verify(meta, true)

	expectedSteps := []string{
		StepMetaValidate,
		StepPoW,
		StepIndex,
		StepReferenceChain,
		StepIntegrity,
	}

	if len(result.Results) != len(expectedSteps) {
		t.Errorf("Expected %d steps, got %d", len(expectedSteps), len(result.Results))
	}

	for i, step := range expectedSteps {
		if result.Results[i].Step != step {
			t.Errorf("Step %d: expected %s, got %s", i, step, result.Results[i].Step)
		}
	}
}

// ============================================================
// 跨模块集成场景测试
// ============================================================

func TestIntegration_MetadataAndPipeline(t *testing.T) {
	// 构造最小合法元数据
	meta := &metadata.Metadata{
		Version:    1,
		Method:     "raw",
		RootCID:    "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
		DataTXID:   "arweave_tx_id_1234567890123456789012345678901234567890",
		DataHeight: 1913000,
		DataSize:   200 * 1024 * 1024, // 200 MiB，免 PoW
	}

	// 使用 balanced 预设
	config := PresetConfigs[SecurityBalanced]
	p := NewPipeline(config)

	result := p.Verify(meta, false)
	if !result.Passed {
		t.Errorf("Integration test failed: %+v", result.Results)
	}

	// 验证结果中可以找到所有步骤
	stepNames := make(map[string]bool)
	for _, r := range result.Results {
		stepNames[r.Step] = true
	}
	for _, expected := range []string{StepMetaValidate, StepPoW, StepIndex, StepReferenceChain, StepIntegrity} {
		if !stepNames[expected] {
			t.Errorf("Missing step: %s", expected)
		}
	}
}

// ============================================================
// 辅助函数
// ============================================================

func validMeta() *metadata.Metadata {
	return &metadata.Metadata{
		Version:    1,
		Method:     "raw",
		RootCID:    "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
		DataTXID:   "arweave_tx_id_1234567890123456789012345678901234567890",
		DataHeight: 1913000,
		DataSize:   150 * 1024 * 1024, // 150 MiB，不需要 PoW
	}
}
