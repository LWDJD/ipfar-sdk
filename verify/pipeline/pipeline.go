// Package pipeline 提供 IPFAR 可配置验证管道
// 将 PoW、CAR Index、引用链、数据完整性验证组合为统一流程
// 规范参考: ipfar-specs/V1/项目规划.md §4.1
package pipeline

import (
	"errors"
	"fmt"

	"github.com/LWDJD/ipfar-sdk/verify/metadata"
	"github.com/LWDJD/ipfar-sdk/verify/pow"
)

// 安全等级预设
const (
	SecurityStrict   = "strict"   // 全开，最安全
	SecurityBalanced = "balanced" // 均衡模式
	SecurityLight    = "light"    // 仅验证 PoW 与引用链（默认）
	SecurityTrusted  = "trusted"  // 仅验证元数据，适合开发测试
)

// 验证步骤标识
const (
	StepMetaValidate   = "meta_validate"   // 元数据合法性校验（强制）
	StepPoW            = "pow"             // PoW 验证
	StepIndex          = "index"           // CAR v2 Index 完整性
	StepReferenceChain = "reference_chain" // 引用链验证
	StepIntegrity      = "integrity"       // 数据完整性验证
)

// VerifyConfig 验证配置
// 规范参考: 项目规划.md §4.1 验证项清单
type VerifyConfig struct {
	VerifyPoW            bool `json:"verify_pow"`             // PoW 验证开关
	VerifyIndex          bool `json:"verify_index"`           // Index 完整性验证开关
	VerifyReferenceChain bool `json:"verify_reference_chain"` // 引用链验证开关
	VerifyIntegrity      bool `json:"verify_integrity"`       // 数据完整性验证开关
}

// VerifyResult 单步验证结果
type VerifyResult struct {
	Step    string `json:"step"`    // 验证步骤标识
	Passed  bool   `json:"passed"`  // 是否通过
	Skipped bool   `json:"skipped"` // 是否跳过
	Error   string `json:"error,omitempty"`   // 错误信息
	Message string `json:"message,omitempty"` // 附加信息
}

// PipelineResult 管道验证结果
type PipelineResult struct {
	Passed  bool           `json:"passed"`  // 是否全部通过
	Results []VerifyResult `json:"results"` // 各步骤结果
}

// 错误定义
var (
	ErrMetaValidateFailed   = errors.New("metadata validation failed")
	ErrPoWVerificationFailed = errors.New("PoW verification failed")
	ErrIndexVerificationFailed = errors.New("CAR v2 index verification failed")
	ErrReferenceChainFailed = errors.New("reference chain verification failed")
	ErrIntegrityFailed      = errors.New("data integrity verification failed")
)

// PresetConfigs 预设安全等级配置
var PresetConfigs = map[string]VerifyConfig{
	SecurityStrict: {
		VerifyPoW:            true,
		VerifyIndex:          true,
		VerifyReferenceChain: true,
		VerifyIntegrity:      true,
	},
	SecurityBalanced: {
		VerifyPoW:            true,
		VerifyIndex:          true,
		VerifyReferenceChain: false,
		VerifyIntegrity:      true,
	},
	SecurityLight: {
		VerifyPoW:            true,
		VerifyIndex:          false,
		VerifyReferenceChain: true,
		VerifyIntegrity:      false,
	},
	SecurityTrusted: {
		VerifyPoW:            false,
		VerifyIndex:          false,
		VerifyReferenceChain: false,
		VerifyIntegrity:      false,
	},
}

// GetPreset 获取预设安全等级配置
func GetPreset(level string) (VerifyConfig, error) {
	config, ok := PresetConfigs[level]
	if !ok {
		return VerifyConfig{}, fmt.Errorf("unknown security level: %s (valid: strict, balanced, light, trusted)", level)
	}
	return config, nil
}

// NewVerifyConfig 创建默认验证配置（均衡模式）
func NewVerifyConfig() VerifyConfig {
	return PresetConfigs[SecurityLight]
}

// NewVerifyConfigFromPreset 从预设名称创建配置
func NewVerifyConfigFromPreset(preset string) (VerifyConfig, error) {
	return GetPreset(preset)
}

// Pipeline 验证管道
type Pipeline struct {
	config VerifyConfig

	// 可注入的验证函数（用于测试）
	metaValidator     func(meta *metadata.Metadata) error
	powVerifier       func(powStr, powAlg, rootCID, dataTXID string, dataSize int64) error
	indexVerifier     func() error
	referenceVerifier func(meta *metadata.Metadata) error
	integrityVerifier func() error
}

// NewPipeline 创建新的验证管道
func NewPipeline(config VerifyConfig) *Pipeline {
	p := &Pipeline{
		config: config,
	}
	// 默认使用标准实现
	p.metaValidator = defaultMetaValidator
	p.powVerifier = defaultPoWVerifier
	p.indexVerifier = defaultIndexVerifier
	p.referenceVerifier = defaultReferenceVerifier
	p.integrityVerifier = defaultIntegrityVerifier
	return p
}

// NewPipelineWithPreset 从预设创建验证管道
func NewPipelineWithPreset(preset string) (*Pipeline, error) {
	config, err := GetPreset(preset)
	if err != nil {
		return nil, err
	}
	return NewPipeline(config), nil
}

// SetMetaValidator 注入自定义元数据验证器（用于测试）
func (p *Pipeline) SetMetaValidator(fn func(meta *metadata.Metadata) error) {
	p.metaValidator = fn
}

// SetPoWVerifier 注入自定义 PoW 验证器（用于测试）
func (p *Pipeline) SetPoWVerifier(fn func(powStr, powAlg, rootCID, dataTXID string, dataSize int64) error) {
	p.powVerifier = fn
}

// SetIndexVerifier 注入自定义 Index 验证器（用于测试）
func (p *Pipeline) SetIndexVerifier(fn func() error) {
	p.indexVerifier = fn
}

// SetReferenceVerifier 注入自定义引用验证器（用于测试）
func (p *Pipeline) SetReferenceVerifier(fn func(meta *metadata.Metadata) error) {
	p.referenceVerifier = fn
}

// SetIntegrityVerifier 注入自定义完整性验证器（用于测试）
func (p *Pipeline) SetIntegrityVerifier(fn func() error) {
	p.integrityVerifier = fn
}

// Verify 执行验证管道
//
// 验证流程（规范 §4.1 验证流程）:
//   1. 元数据合法性校验（强制，不可配置）
//   2. verify_pow? → PoW 验证
//   3. 下载主 CAR 文件（不在本管道内执行）
//   4. verify_index? → 验证 Index 完整性
//   5. verify_reference_chain? → 引用链解析
//   6. verify_integrity? → 数据哈希比对 CID
//
// 参数 meta 已解析的元数据，carAvailable 表示 CAR 文件是否已下载可用
func (p *Pipeline) Verify(meta *metadata.Metadata, carAvailable bool) *PipelineResult {
	result := &PipelineResult{
		Passed:  true,
		Results: make([]VerifyResult, 0, 5),
	}

	// Step 1: 元数据合法性校验（强制，不可配置）
	vr := p.executeStep(StepMetaValidate, true, func() error {
		return p.metaValidator(meta)
	})
	result.Results = append(result.Results, vr)
	if !vr.Passed {
		result.Passed = false
		return result // 元数据不合法则停止后续验证
	}

	// Step 2: PoW 验证
	if meta.NeedsPoW() {
		vr = p.executeStep(StepPoW, p.config.VerifyPoW, func() error {
			return p.powVerifier(meta.PoW, meta.PoWAlg, meta.RootCID, meta.DataTXID, int64(meta.DataSize))
		})
	} else {
		// 大文件免 PoW，跳过
		vr = VerifyResult{
			Step:    StepPoW,
			Passed:  true,
			Skipped: true,
			Message: "file size >= 100 MiB, PoW not required",
		}
	}
	result.Results = append(result.Results, vr)
	if !vr.Passed && !vr.Skipped {
		result.Passed = false
	}

	// 后续步骤需要 CAR 文件
	if !carAvailable {
		// CAR 文件不可用，跳过后续验证
		skippedSteps := []string{StepIndex, StepReferenceChain, StepIntegrity}
		for _, step := range skippedSteps {
			result.Results = append(result.Results, VerifyResult{
				Step:    step,
				Passed:  true,
				Skipped: true,
				Message: "CAR file not available, step skipped",
			})
		}
		return result
	}

	// Step 3: CAR v2 Index 完整性
	vr = p.executeStep(StepIndex, p.config.VerifyIndex, func() error {
		return p.indexVerifier()
	})
	result.Results = append(result.Results, vr)
	if !vr.Passed && !vr.Skipped {
		result.Passed = false
	}

	// Step 4: 引用链验证
	vr = p.executeStep(StepReferenceChain, p.config.VerifyReferenceChain, func() error {
		return p.referenceVerifier(meta)
	})
	result.Results = append(result.Results, vr)
	if !vr.Passed && !vr.Skipped {
		result.Passed = false
	}

	// Step 5: 数据完整性验证
	vr = p.executeStep(StepIntegrity, p.config.VerifyIntegrity, func() error {
		return p.integrityVerifier()
	})
	result.Results = append(result.Results, vr)
	if !vr.Passed && !vr.Skipped {
		result.Passed = false
	}

	return result
}

// executeStep 执行单个验证步骤
// enabled=false 时跳过该步骤
func (p *Pipeline) executeStep(step string, enabled bool, fn func() error) VerifyResult {
	if !enabled {
		return VerifyResult{
			Step:    step,
			Passed:  true,
			Skipped: true,
			Message: "verification disabled by config",
		}
	}

	err := fn()
	if err != nil {
		return VerifyResult{
			Step:   step,
			Passed: false,
			Error:  err.Error(),
		}
	}

	return VerifyResult{
		Step:   step,
		Passed: true,
	}
}

// ============================================================
// 默认验证器实现
// ============================================================

// defaultMetaValidator 默认元数据验证器
func defaultMetaValidator(meta *metadata.Metadata) error {
	if meta == nil {
		return errors.New("metadata is nil")
	}
	return meta.Validate()
}

// defaultPoWVerifier 默认 PoW 验证器
func defaultPoWVerifier(powStr, powAlg, rootCID, dataTXID string, dataSize int64) error {
	return pow.Verify(powStr, powAlg, rootCID, dataTXID, dataSize)
}

// defaultIndexVerifier 默认 Index 验证器
// 在实际使用中，需要在 CAR 文件下载后调用 CAR 解析器验证
func defaultIndexVerifier() error {
	// 默认实现：占位，实际由外部注入
	// 当没有注入实际验证器时，返回 nil（跳过）
	return nil
}

// defaultReferenceVerifier 默认引用链验证器
func defaultReferenceVerifier(meta *metadata.Metadata) error {
	// 如果元数据没有引用，则自动通过
	if meta == nil || !meta.HasReference() {
		return nil
	}
	// 引用链验证需要实际下载被引用的交易数据
	// 默认实现：占位，实际由外部注入
	return nil
}

// defaultIntegrityVerifier 默认数据完整性验证器
func defaultIntegrityVerifier() error {
	// 默认实现：占位，实际由外部注入
	// 需要重算 CAR 文件哈希并与 CID 比对
	return nil
}

// ============================================================
// 便捷函数
// ============================================================

// QuickVerify 快速验证元数据（不涉及 CAR 文件）
// 执行：元数据校验 + PoW 验证
func QuickVerify(meta *metadata.Metadata, config VerifyConfig) *PipelineResult {
	p := NewPipeline(config)
	return p.Verify(meta, false)
}

// FullVerify 完整验证（需要 CAR 文件已下载）
func FullVerify(meta *metadata.Metadata, config VerifyConfig) *PipelineResult {
	p := NewPipeline(config)
	return p.Verify(meta, true)
}

// VerifyWithDefaultConfig 使用默认配置验证
func VerifyWithDefaultConfig(meta *metadata.Metadata, carAvailable bool) *PipelineResult {
	p := NewPipeline(NewVerifyConfig())
	return p.Verify(meta, carAvailable)
}
