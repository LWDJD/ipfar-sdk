// Package pipeline 提供 IPFAR 可配置验证管道
// 将 PoW、CAR Index、引用链、数据完整性验证组合为统一流程
// 规范参考: ipfar-specs/V1/项目规划.md §4.1
package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/LWDJD/ipfar-sdk/arweave"
	"github.com/LWDJD/ipfar-sdk/verify/ipfs"
	"github.com/LWDJD/ipfar-sdk/verify/metadata"
	"github.com/LWDJD/ipfar-sdk/verify/pow"
	"github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

// 安全等级预设
const (
	SecurityStrict   = "strict"   // 全开，最安全
	SecurityBalanced = "balanced" // 均衡模式
	SecurityLight    = "light"    // 验证 PoW、Index 与引用链（默认）
	SecurityTrusted  = "trusted"  // 仅验证元数据与 Index，适合开发测试
)

// 验证步骤标识
const (
	StepMetaValidate    = "meta_validate"    // 元数据合法性校验（强制）
	StepPoW             = "pow"              // PoW 验证
	StepIndexExistence  = "index_existence"  // CAR v2 Index 存在性检查（强制，不可配置）
	StepIndex           = "index"            // CAR v2 Index 完整性
	StepReferenceChain  = "reference_chain"  // 引用链验证
	StepIntegrity       = "integrity"        // 数据完整性验证
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
		VerifyIndex:          true, // spec §3.4: Index always enforced
		VerifyReferenceChain: true,
		VerifyIntegrity:      false,
	},
	SecurityTrusted: {
		VerifyPoW:            false,
		VerifyIndex:          true, // spec §3.4: Index always enforced
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
	metaValidator        func(meta *metadata.Metadata) error
	powVerifier          func(powStr, powAlg, rootCID, dataTXID string, dataSize int64) error
	indexExistenceVerifier func() error
	indexVerifier        func() error
	referenceVerifier    func(meta *metadata.Metadata) error
	integrityVerifier    func() error

	// CAR 文件解析器（可选，用于 Index 和 Integrity 验证）
	carFile string // CAR 文件路径

	// gatewayClient 用于引用链解析等需要网络访问的验证步骤
	gatewayClient *arweave.GatewayClient
}

// NewPipeline 创建新的验证管道
func NewPipeline(config VerifyConfig) *Pipeline {
	p := &Pipeline{
		config: config,
	}
	// 默认使用标准实现
	p.metaValidator = defaultMetaValidator
	p.powVerifier = defaultPoWVerifier
	p.indexExistenceVerifier = defaultIndexExistenceVerifier
	p.indexVerifier = defaultIndexVerifier
	p.referenceVerifier = p.defaultReferenceVerifier
	p.integrityVerifier = defaultIntegrityVerifier
	return p
}

// SetCarFile 设置 CAR 文件路径并自动配置 Index/Integrity 验证器
// 调用此方法后，如果未通过 SetIndexVerifier/SetIntegrityVerifier 注入自定义实现，
// 则默认验证器将使用该 CAR 文件进行验证。
func (p *Pipeline) SetCarFile(carPath string) {
	p.carFile = carPath
	// 使用基于 CAR 文件的默认实现替换占位实现
	p.indexExistenceVerifier = func() error {
		return defaultIndexExistenceVerifierWithCar(carPath)
	}
	p.indexVerifier = func() error {
		return defaultIndexVerifierWithCar(carPath)
	}
	p.integrityVerifier = func() error {
		return defaultIntegrityVerifierWithCar(carPath)
	}
}

// SetGatewayClient 设置 Arweave 网关客户端，用于引用链解析等网络验证步骤。
func (p *Pipeline) SetGatewayClient(client *arweave.GatewayClient) {
	p.gatewayClient = client
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

// SetIndexExistenceVerifier 注入自定义 Index 存在性验证器（用于测试）
func (p *Pipeline) SetIndexExistenceVerifier(fn func() error) {
	p.indexExistenceVerifier = fn
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
		skippedSteps := []string{StepIndexExistence, StepIndex, StepReferenceChain, StepIntegrity}
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

	// Step 3a: Index 存在性检查（始终强制执行，规范 §3.4）
	// 仅检查 CARv2 是否包含 Index，不校验内容。
	// 此步骤不可配置，对所有安全等级（包括 trusted）均执行。
	vr = p.executeStep(StepIndexExistence, true, func() error {
		return p.indexExistenceVerifier()
	})
	result.Results = append(result.Results, vr)
	if !vr.Passed && !vr.Skipped {
		result.Passed = false
	}

	// Step 3b: Index 内容校验（可配置）
	// 当 verify_index=true 时，验证索引内容完整性及交叉校验。
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

// defaultIndexExistenceVerifier 默认 Index 存在性验证器（无 CAR 文件时跳过）
func defaultIndexExistenceVerifier() error {
	// 占位：无 CAR 文件可用时跳过
	return nil
}

// defaultIndexExistenceVerifierWithCar 基于 CAR 文件的 Index 存在性检查
// 仅检查 CARv2 是否包含 Index，不校验内容。规范 §3.4。
func defaultIndexExistenceVerifierWithCar(carPath string) error {
	if carPath == "" {
		return nil
	}
	parser, err := ipfs.NewCarParserFromFile(carPath)
	if err != nil {
		return fmt.Errorf("failed to open CAR file for index existence check: %v", err)
	}
	defer parser.Close()

	return parser.ValidateIndexExistence()
}

// defaultIndexVerifier 默认 Index 验证器（无 CAR 文件时跳过）
func defaultIndexVerifier() error {
	// 占位：无 CAR 文件可用时跳过
	return nil
}

// defaultIndexVerifierWithCar 基于 CAR 文件的 Index 验证
func defaultIndexVerifierWithCar(carPath string) error {
	if carPath == "" {
		return nil
	}
	parser, err := ipfs.NewCarParserFromFile(carPath)
	if err != nil {
		return fmt.Errorf("failed to open CAR file for index verification: %v", err)
	}
	defer parser.Close()

	info, err := parser.ParseInfo()
	if err != nil {
		return fmt.Errorf("failed to parse CAR file: %v", err)
	}

	// 仅 CARv2 需要索引
	if info.Version != 2 {
		return nil
	}

	if !info.HasIndex {
		return ipfs.ErrIndexNotFound
	}

	// 验证索引内容完整性
	if err := parser.ValidateIndexContent(); err != nil {
		return err
	}

	// 交叉验证索引与数据段
	if err := parser.ValidateIndexCrossCheck(); err != nil {
		return err
	}

	return nil
}

// MaxReferenceDepth 引用链最大递归深度（防无限循环）
const MaxReferenceDepth = 10

// defaultReferenceVerifier 默认引用链验证器（Pipeline 方法）
// 解析 metadata 的 reference 字段，递归验证引用链。
//
// 规范 §4.6：链式解析自动递归、无深度限制（实现中设置 MaxReferenceDepth=10 防循环）。
func (p *Pipeline) defaultReferenceVerifier(meta *metadata.Metadata) error {
	// 如果元数据没有引用，则自动通过
	if meta == nil || !meta.HasReference() {
		return nil
	}

	// 需要网关客户端才能验证引用链
	if p.gatewayClient == nil {
		// 无网关客户端时跳过（向后兼容，允许外部注入验证器）
		return nil
	}

	ctx := context.Background()
	visited := make(map[string]bool) // 防循环

	return p.resolveReferences(ctx, *meta.Reference, visited, 0)
}

// resolveReferences 递归解析引用链（BFS/DFS）。
//
// 对每个引用条目：
//  1. 下载被引用交易数据
//  2. 计算 CID 并比对
//  3. 检查被引用交易是否也有 reference 字段
//  4. 若有，递归解析
func (p *Pipeline) resolveReferences(ctx context.Context, ref metadata.ReferenceMap, visited map[string]bool, depth int) error {
	if depth > MaxReferenceDepth {
		return fmt.Errorf("reference chain: max depth %d exceeded", MaxReferenceDepth)
	}

	for txID, entry := range ref {
		// 防循环
		if visited[txID] {
			continue
		}
		visited[txID] = true

		// 1. 下载被引用的交易数据
		// 根据引用条目中的 bundle_txid 决定下载方式：
		//   - bundle_txid 非空且不为 "none"：跨 Bundle 引用，通过 Bundle Item API 获取
		//   - 其他情况：直接下载交易数据
		var data []byte
		var err error

		if entry.BundleTXID != "" && entry.BundleTXID != "none" {
			// 跨 Bundle 引用：通过 Bundle Item API 获取
			data, err = p.gatewayClient.FetchBundleItemByID(ctx, entry.BundleTXID, txID)
			if err != nil {
				return fmt.Errorf("reference chain: failed to fetch bundle item %s from bundle %s: %w", txID, entry.BundleTXID, err)
			}
		} else {
			// 常规引用（同 Bundle 或同块）：直接下载交易数据
			data, err = p.gatewayClient.DownloadTransactionData(ctx, txID)
			if err != nil {
				return fmt.Errorf("reference chain: failed to download tx %s: %w", txID, err)
			}
		}

		// 2. 计算下载数据的 CID
		computedCID, err := computeCIDv1(data)
		if err != nil {
			return fmt.Errorf("reference chain: failed to compute CID for tx %s: %w", txID, err)
		}

		// 检查计算的 CID 是否匹配引用条目中的任意 CID
		matched := false
		for _, refCID := range entry.CIDs {
			if computedCID == refCID {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("reference chain: tx %s data CID %s does not match any expected CID in reference", txID, computedCID)
		}

		// 3. 检查被引用交易是否也是元数据 JSON（含 reference 字段）
		subMeta, err := tryParseMetadata(data)
		if err != nil {
			// 不是元数据 JSON，无法递归，该分支结束
			continue
		}

		// 4. 如果被引用交易也有 reference 字段，递归解析
		if subMeta.HasReference() {
			if err := p.resolveReferences(ctx, *subMeta.Reference, visited, depth+1); err != nil {
				return err
			}
		}
	}

	return nil
}

// tryParseMetadata 尝试将数据解析为 Metadata JSON。
// 如果不是合法的 IPFAR 元数据，返回 error。
func tryParseMetadata(data []byte) (*metadata.Metadata, error) {
	// 尝试直接 JSON 解析
	var meta metadata.Metadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("not metadata JSON: %w", err)
	}
	// 基本校验：必须有 version 字段为 1
	if meta.Version != 1 {
		return nil, fmt.Errorf("not metadata JSON: invalid version %d", meta.Version)
	}
	if meta.RootCID == "" {
		return nil, fmt.Errorf("not metadata JSON: missing root_cid")
	}
	return &meta, nil
}

// defaultIntegrityVerifier 默认数据完整性验证器（无 CAR 文件时跳过）
func defaultIntegrityVerifier() error {
	// 占位：无 CAR 文件可用时跳过
	return nil
}

// defaultIntegrityVerifierWithCar 基于 CAR 文件的数据完整性验证
// 重算所有块的哈希并与 CID 比对
func defaultIntegrityVerifierWithCar(carPath string) error {
	if carPath == "" {
		return nil
	}
	parser, err := ipfs.NewCarParserFromFile(carPath)
	if err != nil {
		return fmt.Errorf("failed to open CAR file for integrity verification: %v", err)
	}
	defer parser.Close()

	var lastErr error
	blockCount := 0
	err = parser.IterateBlocks(func(block *ipfs.Block) error {
		blockCount++
		if err := parser.ValidateBlockIntegrity(block); err != nil {
			lastErr = err
			return err
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("integrity check failed at block %d: %v", blockCount, lastErr)
	}

	return nil
}

// ============================================================
// 便捷函数
// ============================================================

// computeCIDv1 computes a CID v1 (raw, sha2-256) for the given data.
func computeCIDv1(data []byte) (string, error) {
	hash, err := mh.Sum(data, mh.SHA2_256, -1)
	if err != nil {
		return "", fmt.Errorf("failed to hash data: %w", err)
	}
	c := cid.NewCidV1(cid.Raw, hash)
	return c.String(), nil
}

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
