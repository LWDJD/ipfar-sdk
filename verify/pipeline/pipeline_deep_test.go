package pipeline

import (
	"testing"

	"github.com/LWDJD/ipfar-sdk/verify/metadata"
)

// ============================================================
// All 4 presets verification
// ============================================================

func TestPresetConfigs_AllValid(t *testing.T) {
	presets := []struct {
		name   string
		preset string
	}{
		{"strict", SecurityStrict},
		{"balanced", SecurityBalanced},
		{"light", SecurityLight},
		{"trusted", SecurityTrusted},
	}

	for _, p := range presets {
		t.Run(p.name, func(t *testing.T) {
			cfg, err := GetPreset(p.preset)
			if err != nil {
				t.Fatalf("GetPreset(%s) failed: %v", p.preset, err)
			}

			// Verify each preset has the correct settings
			switch p.preset {
			case SecurityStrict:
				if !cfg.VerifyPoW || !cfg.VerifyIndex || !cfg.VerifyReferenceChain || !cfg.VerifyIntegrity {
					t.Error("strict should have all verifications enabled")
				}
			case SecurityBalanced:
				if !cfg.VerifyPoW || !cfg.VerifyIndex || cfg.VerifyReferenceChain || !cfg.VerifyIntegrity {
					t.Error("balanced should have PoW+Index+Integrity, no Reference")
				}
			case SecurityLight:
				if !cfg.VerifyPoW || cfg.VerifyIndex || !cfg.VerifyReferenceChain || cfg.VerifyIntegrity {
					t.Error("light should have PoW+ReferenceChain, no Index/Integrity")
				}
			case SecurityTrusted:
				if cfg.VerifyPoW || cfg.VerifyIndex || cfg.VerifyReferenceChain || cfg.VerifyIntegrity {
					t.Error("trusted should have all verifications disabled")
				}
			}
		})
	}
}

func TestGetPreset_Invalid_Deep(t *testing.T) {
	_, err := GetPreset("invalid")
	if err == nil {
		t.Fatal("expected error for invalid preset")
	}
}

func TestNewVerifyConfigFromPreset_All(t *testing.T) {
	for _, preset := range []string{SecurityStrict, SecurityBalanced, SecurityLight, SecurityTrusted} {
		cfg, err := NewVerifyConfigFromPreset(preset)
		if err != nil {
			t.Errorf("NewVerifyConfigFromPreset(%s) failed: %v", preset, err)
		}
		_ = cfg
	}
}

// ============================================================
// Pipeline creation with all presets
// ============================================================

func TestNewPipelineWithPreset_All(t *testing.T) {
	for _, preset := range []string{SecurityStrict, SecurityBalanced, SecurityLight, SecurityTrusted} {
		p, err := NewPipelineWithPreset(preset)
		if err != nil {
			t.Errorf("NewPipelineWithPreset(%s) failed: %v", preset, err)
			continue
		}
		if p == nil {
			t.Errorf("NewPipelineWithPreset(%s) returned nil", preset)
		}
	}
}

func TestNewPipelineWithPreset_Invalid_Deep(t *testing.T) {
	_, err := NewPipelineWithPreset("nonexistent")
	if err == nil {
		t.Fatal("expected error for invalid preset")
	}
}

// ============================================================
// Verify with all presets — metadata only (no CAR)
// ============================================================

func TestVerify_AllPresets_MetaOnly(t *testing.T) {
	meta := &metadata.Metadata{
		Version:    1,
		Method:     "raw",
		RootCID:    "bafyAllPresetsCID12345678901234567890123456789012",
		DataTXID:   "all_presets_tx_12345678901234567890123456789012345",
		DataHeight: 100,
		DataSize:   200 * 1024 * 1024, // No PoW needed
	}

	for _, preset := range []string{SecurityStrict, SecurityBalanced, SecurityLight, SecurityTrusted} {
		t.Run(preset, func(t *testing.T) {
			p, err := NewPipelineWithPreset(preset)
			if err != nil {
				t.Fatalf("failed to create pipeline: %v", err)
			}

			result := p.Verify(meta, false) // No CAR
			if result == nil {
				t.Fatal("Verify returned nil")
			}

			// All should pass metadata validation
			// PoW step should be skipped (large file)
			// CAR steps should be skipped (no CAR)

			if !result.Passed {
				t.Errorf("preset %s: expected passed, got %+v", preset, result)
			}

			// Count steps
			if len(result.Results) == 0 {
				t.Error("expected at least 1 result")
			}

			t.Logf("preset %s: %d steps, passed=%v", preset, len(result.Results), result.Passed)
		})
	}
}

// ============================================================
// Verify nil metadata
// ============================================================

func TestVerify_NilMetadata_Deep(t *testing.T) {
	p := NewPipeline(NewVerifyConfig())
	result := p.Verify(nil, false)

	if result.Passed {
		t.Error("nil metadata should fail")
	}

	// First step should be meta_validate and should fail
	if len(result.Results) == 0 {
		t.Fatal("expected at least 1 result")
	}
	if result.Results[0].Step != StepMetaValidate {
		t.Errorf("first step should be %s, got %s", StepMetaValidate, result.Results[0].Step)
	}
	if result.Results[0].Passed {
		t.Error("meta_validate should fail for nil metadata")
	}
}

// ============================================================
// Meta validation with custom validator
// ============================================================

func TestPipeline_CustomMetaValidator_Deep(t *testing.T) {
	p := NewPipeline(NewVerifyConfig())

	callCount := 0
	p.SetMetaValidator(func(meta *metadata.Metadata) error {
		callCount++
		return nil // always pass
	})

	meta := &metadata.Metadata{
		Version:    1,
		Method:     "raw",
		RootCID:    "bafyCustomMeta12345678901234567890123456789012345",
		DataTXID:   "custom_meta_tx_1234567890123456789012345678901234",
		DataHeight: 100,
		DataSize:   200 * 1024 * 1024,
	}

	result := p.Verify(meta, false)
	if callCount != 1 {
		t.Errorf("custom meta validator should be called once, got %d", callCount)
	}
	if !result.Passed {
		t.Error("custom validator (always pass) should pass")
	}
}

// ============================================================
// Custom PoW verifier
// ============================================================

func TestPipeline_CustomPoWVerifier(t *testing.T) {
	cfg := NewVerifyConfig()
	cfg.VerifyPoW = true

	p := NewPipeline(cfg)

	callCount := 0
	p.SetPoWVerifier(func(powStr, powAlg, rootCID, dataTXID string, dataSize int64) error {
		callCount++
		return nil // always pass
	})

	meta := &metadata.Metadata{
		Version:    1,
		Method:     "raw",
		RootCID:    "bafyCustomPoW12345678901234567890123456789012345",
		DataTXID:   "custom_pow_tx_1234567890123456789012345678901234",
		DataHeight: 100,
		DataSize:   1024, // Small file, needs PoW
		PoW:        "12345",
		PoWAlg:     "argon2id-light-v1",
	}

	result := p.Verify(meta, false)
	if callCount != 1 {
		t.Errorf("custom PoW verifier should be called once, got %d", callCount)
	}
	if !result.Passed {
		t.Error("custom PoW verifier (always pass) should pass")
	}
}

// ============================================================
// Custom reference verifier
// ============================================================

func TestPipeline_CustomReferenceVerifier(t *testing.T) {
	cfg := NewVerifyConfig()
	cfg.VerifyReferenceChain = true

	p := NewPipeline(cfg)

	callCount := 0
	p.SetReferenceVerifier(func(meta *metadata.Metadata) error {
		callCount++
		return nil
	})

	ref := metadata.ReferenceMap{
		"tx_ref_123456789012345678901234567890123456789012": {
			Height: 100,
			CIDs:   []string{"bafyRefCID"},
		},
	}

	meta := &metadata.Metadata{
		Version:    1,
		Method:     "raw",
		RootCID:    "bafyCustomRef1234567890123456789012345678901234",
		DataTXID:   "custom_ref_tx_123456789012345678901234567890123",
		DataHeight: 100,
		DataSize:   200 * 1024 * 1024,
		Reference:  &ref,
	}

	result := p.Verify(meta, true) // With CAR
	if callCount != 1 {
		t.Errorf("custom reference verifier should be called once, got %d", callCount)
	}
	if !result.Passed {
		t.Error("custom reference verifier (always pass) should pass")
	}
}

// ============================================================
// VerifyReferenceChain — nil metadata
// ============================================================

func TestVerifyReferenceChain_NilMeta(t *testing.T) {
	p := NewPipeline(NewVerifyConfig())
	vr, err := p.VerifyReferenceChain(nil)
	if err == nil {
		t.Fatal("expected error for nil metadata")
	}
	if vr.Passed {
		t.Error("nil metadata should not pass")
	}
	if !vr.Incomplete {
		t.Error("nil metadata should be marked incomplete")
	}
}

// ============================================================
// VerifyReferenceChain — no reference
// ============================================================

func TestVerifyReferenceChain_NoReference(t *testing.T) {
	p := NewPipeline(NewVerifyConfig())
	meta := &metadata.Metadata{
		Version:    1,
		Method:     "raw",
		RootCID:    "bafyNoRef123456789012345678901234567890123456789",
		DataTXID:   "no_ref_tx_12345678901234567890123456789012345678",
		DataHeight: 100,
		DataSize:   200 * 1024 * 1024,
	}

	vr, err := p.VerifyReferenceChain(meta)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !vr.Passed {
		t.Error("metadata without reference should pass (skipped)")
	}
	if !vr.Skipped {
		t.Error("should be marked as skipped")
	}
}

// ============================================================
// ReferenceIncompleteError
// ============================================================

func TestReferenceIncompleteError(t *testing.T) {
	e := &ReferenceIncompleteError{
		Errors: []string{"tx A: download failed", "tx B: CID mismatch"},
	}
	errStr := e.Error()
	if errStr == "" {
		t.Error("error string should not be empty")
	}
	t.Logf("ReferenceIncompleteError: %s", errStr)
}

// ============================================================
// QuickVerify / FullVerify
// ============================================================

func TestQuickVerify_Deep(t *testing.T) {
	meta := &metadata.Metadata{
		Version:    1,
		Method:     "raw",
		RootCID:    "bafyQuick12345678901234567890123456789012345678901",
		DataTXID:   "quick_tx_1234567890123456789012345678901234567890",
		DataHeight: 100,
		DataSize:   200 * 1024 * 1024,
	}

	result := QuickVerify(meta, NewVerifyConfig())
	if !result.Passed {
		t.Errorf("QuickVerify should pass: %+v", result)
	}

	// CAR-dependent steps should be skipped
	for _, r := range result.Results {
		if r.Step == StepIndex || r.Step == StepIntegrity || r.Step == StepReferenceChain {
			if !r.Skipped {
				t.Errorf("step %s should be skipped in QuickVerify", r.Step)
			}
		}
	}
}

func TestFullVerify_Deep(t *testing.T) {
	// FullVerify with metadata but no actual CAR — meta should still pass
	meta := &metadata.Metadata{
		Version:    1,
		Method:     "raw",
		RootCID:    "bafyFull123456789012345678901234567890123456789012",
		DataTXID:   "full_tx_12345678901234567890123456789012345678901",
		DataHeight: 100,
		DataSize:   200 * 1024 * 1024,
	}

	result := FullVerify(meta, NewVerifyConfig())
	if !result.Passed {
		t.Errorf("FullVerify should pass metadata: %+v", result)
	}
}

func TestVerifyWithDefaultConfig_Deep(t *testing.T) {
	meta := &metadata.Metadata{
		Version:    1,
		Method:     "raw",
		RootCID:    "bafyDefault1234567890123456789012345678901234567890",
		DataTXID:   "default_tx_123456789012345678901234567890123456789",
		DataHeight: 100,
		DataSize:   200 * 1024 * 1024,
	}

	result := VerifyWithDefaultConfig(meta, false)
	if !result.Passed {
		t.Errorf("VerifyWithDefaultConfig should pass: %+v", result)
	}
}

// ============================================================
// Execute step with incomplete
// ============================================================

func TestExecuteStepWithIncomplete_FullPass(t *testing.T) {
	p := NewPipeline(NewVerifyConfig())
	vr := p.executeStepWithIncomplete("test_step", true, func() (bool, error) {
		return false, nil // complete success
	})

	if !vr.Passed {
		t.Error("should pass")
	}
	if vr.Incomplete {
		t.Error("should not be incomplete")
	}
}

func TestExecuteStepWithIncomplete_Incomplete(t *testing.T) {
	p := NewPipeline(NewVerifyConfig())
	vr := p.executeStepWithIncomplete("test_step", true, func() (bool, error) {
		return true, &ReferenceIncompleteError{Errors: []string{"partial failure"}}
	})

	if !vr.Passed {
		t.Error("incomplete step should still pass")
	}
	if !vr.Incomplete {
		t.Error("should be marked incomplete")
	}
}

func TestExecuteStepWithIncomplete_HardFail(t *testing.T) {
	p := NewPipeline(NewVerifyConfig())
	vr := p.executeStepWithIncomplete("test_step", true, func() (bool, error) {
		return false, ErrReferenceChainFailed
	})

	if vr.Passed {
		t.Error("hard failure should not pass")
	}
	if vr.Incomplete {
		t.Error("hard failure should not be marked incomplete")
	}
}

func TestExecuteStepWithIncomplete_Disabled(t *testing.T) {
	p := NewPipeline(NewVerifyConfig())
	vr := p.executeStepWithIncomplete("test_step", false, func() (bool, error) {
		return false, nil
	})

	if !vr.Passed {
		t.Error("disabled step should pass")
	}
	if !vr.Skipped {
		t.Error("disabled step should be skipped")
	}
}

// ============================================================
// Execute step
// ============================================================

func TestExecuteStep_EnabledPass(t *testing.T) {
	p := NewPipeline(NewVerifyConfig())
	vr := p.executeStep("test_step", true, func() error {
		return nil
	})

	if !vr.Passed {
		t.Error("should pass")
	}
	if vr.Skipped {
		t.Error("should not be skipped")
	}
}

func TestExecuteStep_EnabledFail(t *testing.T) {
	p := NewPipeline(NewVerifyConfig())
	vr := p.executeStep("test_step", true, func() error {
		return ErrMetaValidateFailed
	})

	if vr.Passed {
		t.Error("should fail")
	}
	if vr.Error == "" {
		t.Error("should have error message")
	}
}

func TestExecuteStep_Disabled(t *testing.T) {
	p := NewPipeline(NewVerifyConfig())
	vr := p.executeStep("test_step", false, func() error {
		return nil
	})

	if !vr.Passed {
		t.Error("disabled step should pass")
	}
	if !vr.Skipped {
		t.Error("disabled step should be skipped")
	}
}

// ============================================================
// Pipeline with meta having PoW
// ============================================================

func TestVerify_SmallFileWithPoW(t *testing.T) {
	cfg := NewVerifyConfig()
	cfg.VerifyPoW = true

	p := NewPipeline(cfg)

	// Inject a custom PoW verifier that passes
	p.SetPoWVerifier(func(powStr, powAlg, rootCID, dataTXID string, dataSize int64) error {
		return nil
	})

	meta := &metadata.Metadata{
		Version:    1,
		Method:     "raw",
		RootCID:    "bafySmallPoW12345678901234567890123456789012345678",
		DataTXID:   "small_pow_tx_123456789012345678901234567890123456",
		DataHeight: 100,
		DataSize:   1024, // Small file
		PoW:        "42",
		PoWAlg:     "argon2id-light-v1",
	}

	result := p.Verify(meta, false)
	if !result.Passed {
		t.Errorf("small file with PoW should pass: %+v", result)
	}

	// Find PoW step
	found := false
	for _, r := range result.Results {
		if r.Step == StepPoW {
			found = true
			if !r.Passed {
				t.Error("PoW step should pass")
			}
			if r.Skipped {
				t.Error("PoW step should not be skipped for small file")
			}
		}
	}
	if !found {
		t.Error("expected PoW step in results")
	}
}

// ============================================================
// Pipeline: large file skips PoW
// ============================================================

func TestVerify_LargeFileSkipsPoW(t *testing.T) {
	cfg := NewVerifyConfig()
	cfg.VerifyPoW = true

	p := NewPipeline(cfg)
	p.SetPoWVerifier(func(powStr, powAlg, rootCID, dataTXID string, dataSize int64) error {
		t.Error("PoW verifier should not be called for large file")
		return nil
	})

	meta := &metadata.Metadata{
		Version:    1,
		Method:     "raw",
		RootCID:    "bafyLargeSkip1234567890123456789012345678901234567",
		DataTXID:   "large_skip_tx_12345678901234567890123456789012345",
		DataHeight: 100,
		DataSize:   200 * 1024 * 1024, // Large file
	}

	result := p.Verify(meta, false)
	if !result.Passed {
		t.Errorf("large file should pass: %+v", result)
	}

	// Find PoW step — should be skipped
	for _, r := range result.Results {
		if r.Step == StepPoW {
			if !r.Skipped {
				t.Error("PoW should be skipped for large file")
			}
		}
	}
}

// ============================================================
// SetCarFile / SetGatewayClient
// ============================================================

func TestSetCarFile(t *testing.T) {
	p := NewPipeline(NewVerifyConfig())
	p.SetCarFile("/nonexistent/path.car")

	// The verifiers should be set to non-nil
	if p.indexExistenceVerifier == nil {
		t.Error("indexExistenceVerifier should be set")
	}
	if p.indexVerifier == nil {
		t.Error("indexVerifier should be set")
	}
	if p.integrityVerifier == nil {
		t.Error("integrityVerifier should be set")
	}
}

func TestSetGatewayClient_Nil(t *testing.T) {
	p := NewPipeline(NewVerifyConfig())
	p.SetGatewayClient(nil)
	// Should not panic
}
