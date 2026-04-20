// Package arweave 提供 Arweave 区块的解析和验证功能
// 支持从本地文件或远程网关按需获取数据，实现轻量级和全量验证
package arweave

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// defaultTimeout HTTP 请求默认超时时间
const defaultTimeout = 30 * time.Second

// Block 表示一个完整的 Arweave 区块
type Block struct {
	Nonce                    string         `json:"nonce"`
	PreviousBlock            string         `json:"previous_block"`
	Timestamp                int64          `json:"timestamp"`
	LastRetarget             int64          `json:"last_retarget"`
	Diff                     StringOrNumber `json:"diff"`
	Height                   int64          `json:"height"`
	Hash                     string         `json:"hash"`
	IndepHash                string         `json:"indep_hash"`
	Txs                      []string       `json:"txs"`
	TxRoot                   string         `json:"tx_root"`
	WalletList               string         `json:"wallet_list"`
	RewardAddr               string         `json:"reward_addr"`
	Tags                     []Tag          `json:"tags"`
	RewardPool               StringOrNumber `json:"reward_pool"`
	WeaveSize                StringOrNumber `json:"weave_size"`
	BlockSize                StringOrNumber `json:"block_size"`
	CumulativeDiff           StringOrNumber `json:"cumulative_diff"`
	HashListMerkle           string         `json:"hash_list_merkle"`
	POA                      *ProofOfAccess `json:"poa"`
	USDToARRate              []string       `json:"usd_to_ar_rate"`
	ScheduledUSDToARRate     []string       `json:"scheduled_usd_to_ar_rate"`
	Packing25Threshold       StringOrNumber `json:"packing_2_5_threshold"`
	StrictDataSplitThreshold StringOrNumber `json:"strict_data_split_threshold"`
}

// StringOrNumber 支持 JSON 中的字符串或数字类型
// 用于处理 Arweave API 中某些字段在不同区块高度使用不同数据类型的问题
type StringOrNumber string

// UnmarshalJSON 实现自定义的 JSON 反序列化
// 将数字或字符串统一转换为字符串类型
func (sn *StringOrNumber) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		*sn = ""
		return nil
	}

	// 如果是引号包围的字符串，直接解析
	if data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*sn = StringOrNumber(s)
		return nil
	}

	// 否则当作数字处理，转换为字符串
	*sn = StringOrNumber(string(data))
	return nil
}

// String 返回字符串表示
func (sn StringOrNumber) String() string {
	return string(sn)
}

// ProofOfAccess 表示访问证明结构
type ProofOfAccess struct {
	Option   string `json:"option"`
	TxPath   string `json:"tx_path"`
	DataPath string `json:"data_path"`
	Chunk    string `json:"chunk"`
}

// BlockHeader 区块头部信息，用于轻量验证
type BlockHeader struct {
	Height        int64  `json:"height"`
	Hash          string `json:"hash"`
	IndepHash     string `json:"indep_hash"`
	PreviousBlock string `json:"previous_block"`
	Timestamp     int64  `json:"timestamp"`
	TxRoot        string `json:"tx_root"`
	Nonce         string `json:"nonce"`
	Diff          string `json:"diff"`
}

// BlockParser 区块解析器，支持从 io.ReaderAt 或 URL 读取数据
type BlockParser struct {
	reader io.ReaderAt  // 数据源读取接口
	url    string       // 远程数据 URL
	client *http.Client // HTTP 客户端
	block  *Block       // 解析后的区块数据
	header *BlockHeader // 解析后的区块头部
}

// BlockVerificationResult 区块验证结果
type BlockVerificationResult struct {
	Height           int64    // 区块高度
	IndepHash        string   // 区块独立哈希
	IsValid          bool     // 是否有效
	VerificationType string   // 验证类型：light 或 full
	Errors           []string // 验证错误列表
}

// NewBlockParser 创建新的区块解析器（从 io.ReaderAt）
func NewBlockParser(reader io.ReaderAt) *BlockParser {
	return &BlockParser{
		reader: reader,
		client: &http.Client{},
	}
}

// NewBlockParserFromURL 从 URL 创建新的区块解析器
func NewBlockParserFromURL(url string) *BlockParser {
	return &BlockParser{
		url:    url,
		client: &http.Client{Timeout: defaultTimeout},
	}
}

// ParseHeader 解析区块头部信息
// 仅读取必要的头部字段，用于轻量验证
func (p *BlockParser) ParseHeader() error {
	if p.reader != nil {
		return p.parseHeaderFromReader()
	}
	if p.url != "" {
		return p.parseHeaderFromURL()
	}
	return errors.New("no data source configured")
}

// parseHeaderFromReader 从 io.ReaderAt 解析区块头部
func (p *BlockParser) parseHeaderFromReader() error {
	if p.reader == nil {
		return errors.New("reader not set")
	}

	buf := make([]byte, 1024)
	n, err := p.reader.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		return fmt.Errorf("failed to read block header: %v", err)
	}

	var block Block
	if err := json.Unmarshal(buf[:n], &block); err != nil {
		return fmt.Errorf("failed to parse block JSON: %v", err)
	}

	p.block = &block
	p.header = &BlockHeader{
		Height:        block.Height,
		Hash:          block.Hash,
		IndepHash:     block.IndepHash,
		PreviousBlock: block.PreviousBlock,
		Timestamp:     block.Timestamp,
		TxRoot:        block.TxRoot,
		Nonce:         block.Nonce,
		Diff:          block.Diff.String(),
	}

	return nil
}

// parseHeaderFromURL 从 URL 解析区块头部
// 使用 HTTP Range 请求仅获取头部数据
func (p *BlockParser) parseHeaderFromURL() error {
	if p.url == "" {
		return errors.New("URL not set")
	}

	req, err := http.NewRequest("GET", p.url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Range", "bytes=0-4095")
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch block header: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP status: %d", resp.StatusCode)
	}

	buf, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return fmt.Errorf("failed to read response: %v", err)
	}

	var block Block
	if err := json.Unmarshal(buf, &block); err != nil {
		return fmt.Errorf("failed to parse block JSON: %v", err)
	}

	p.block = &block
	p.header = &BlockHeader{
		Height:        block.Height,
		Hash:          block.Hash,
		IndepHash:     block.IndepHash,
		PreviousBlock: block.PreviousBlock,
		Timestamp:     block.Timestamp,
		TxRoot:        block.TxRoot,
		Nonce:         block.Nonce,
		Diff:          block.Diff.String(),
	}

	return nil
}

// ParseFull 解析完整的区块数据
// 读取所有字段，包括交易列表、POA 等
func (p *BlockParser) ParseFull() error {
	if p.reader != nil {
		return p.parseFullFromReader()
	}
	if p.url != "" {
		return p.parseFullFromURL()
	}
	return errors.New("no data source configured")
}

// parseFullFromReader 从 io.ReaderAt 解析完整区块
func (p *BlockParser) parseFullFromReader() error {
	buf := make([]byte, 1024*1024)
	n, err := p.reader.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		return fmt.Errorf("failed to read block data: %v", err)
	}

	var block Block
	if err := json.Unmarshal(buf[:n], &block); err != nil {
		return fmt.Errorf("failed to parse block JSON: %v", err)
	}

	p.block = &block
	p.header = &BlockHeader{
		Height:        block.Height,
		Hash:          block.Hash,
		IndepHash:     block.IndepHash,
		PreviousBlock: block.PreviousBlock,
		Timestamp:     block.Timestamp,
		TxRoot:        block.TxRoot,
		Nonce:         block.Nonce,
		Diff:          block.Diff.String(),
	}

	return nil
}

// parseFullFromURL 从 URL 解析完整区块
func (p *BlockParser) parseFullFromURL() error {
	resp, err := p.client.Get(p.url)
	if err != nil {
		return fmt.Errorf("failed to fetch block: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP status: %d", resp.StatusCode)
	}

	var block Block
	if err := json.NewDecoder(resp.Body).Decode(&block); err != nil {
		return fmt.Errorf("failed to parse block JSON: %v", err)
	}

	p.block = &block
	p.header = &BlockHeader{
		Height:        block.Height,
		Hash:          block.Hash,
		IndepHash:     block.IndepHash,
		PreviousBlock: block.PreviousBlock,
		Timestamp:     block.Timestamp,
		TxRoot:        block.TxRoot,
		Nonce:         block.Nonce,
		Diff:          block.Diff.String(),
	}

	return nil
}

// GetBlock 返回已解析的区块数据
func (p *BlockParser) GetBlock() (*Block, error) {
	if p.block == nil {
		return nil, errors.New("block not parsed, call ParseHeader or ParseFull first")
	}
	return p.block, nil
}

// GetHeader 返回已解析的区块头部
func (p *BlockParser) GetHeader() (*BlockHeader, error) {
	if p.header == nil {
		return nil, errors.New("header not parsed, call ParseHeader first")
	}
	return p.header, nil
}

// VerifyLight 轻量验证区块
// 仅验证必要字段：高度、哈希格式、时间戳、前一个区块哈希
func (p *BlockParser) VerifyLight() (*BlockVerificationResult, error) {
	result := &BlockVerificationResult{
		VerificationType: "light",
		Errors:           []string{},
	}

	if p.header == nil {
		if err := p.ParseHeader(); err != nil {
			return nil, fmt.Errorf("failed to parse header: %v", err)
		}
	}

	result.Height = p.header.Height
	result.IndepHash = p.header.IndepHash

	if err := validateBlockHeader(p.header); err != nil {
		result.Errors = append(result.Errors, err.Error())
	}

	result.IsValid = len(result.Errors) == 0
	return result, nil
}

// VerifyFull 全量验证区块
// 验证所有字段：头部、交易列表、POA、Merkle 根等
func (p *BlockParser) VerifyFull() (*BlockVerificationResult, error) {
	result := &BlockVerificationResult{
		VerificationType: "full",
		Errors:           []string{},
	}

	if p.block == nil {
		if err := p.ParseFull(); err != nil {
			return nil, fmt.Errorf("failed to parse full block: %v", err)
		}
	}

	result.Height = p.block.Height
	result.IndepHash = p.block.IndepHash

	if err := validateBlockHeader(p.header); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("header: %v", err))
	}

	if err := validateBlockTransactions(p.block); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("transactions: %v", err))
	}

	if p.block.POA != nil {
		if err := validateProofOfAccess(p.block.POA); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("POA: %v", err))
		}
	}

	if err := validateBlockMerkleRoot(p.block); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("merkle root: %v", err))
	}

	result.IsValid = len(result.Errors) == 0
	return result, nil
}

// validateBlockHeader 验证区块头部的合法性
func validateBlockHeader(header *BlockHeader) error {
	if header.Height < 0 {
		return errors.New("invalid block height")
	}

	if header.IndepHash == "" {
		return errors.New("missing indep_hash")
	}

	if _, err := base64.RawURLEncoding.DecodeString(header.IndepHash); err != nil {
		return fmt.Errorf("invalid indep_hash format: %v", err)
	}

	if header.PreviousBlock != "" {
		if _, err := base64.RawURLEncoding.DecodeString(header.PreviousBlock); err != nil {
			return fmt.Errorf("invalid previous_block format: %v", err)
		}
	}

	if header.Timestamp <= 0 {
		return errors.New("invalid timestamp")
	}

	if header.Nonce == "" {
		return errors.New("missing nonce")
	}

	return nil
}

// validateBlockTransactions 验证区块交易列表
func validateBlockTransactions(block *Block) error {
	if block.Txs == nil {
		return errors.New("missing transactions list")
	}

	for i, txID := range block.Txs {
		if txID == "" {
			return fmt.Errorf("empty transaction ID at index %d", i)
		}

		if _, err := base64.RawURLEncoding.DecodeString(txID); err != nil {
			return fmt.Errorf("invalid transaction ID format at index %d: %v", i, err)
		}
	}

	return nil
}

// validateProofOfAccess 验证访问证明
func validateProofOfAccess(poa *ProofOfAccess) error {
	if poa.Option == "" {
		return errors.New("missing POA option")
	}

	if poa.TxPath == "" {
		return errors.New("missing POA tx_path")
	}

	if poa.DataPath == "" {
		return errors.New("missing POA data_path")
	}

	if poa.Chunk == "" {
		return errors.New("missing POA chunk")
	}

	if _, err := base64.RawURLEncoding.DecodeString(poa.TxPath); err != nil {
		return fmt.Errorf("invalid POA tx_path format: %v", err)
	}

	if _, err := base64.RawURLEncoding.DecodeString(poa.DataPath); err != nil {
		return fmt.Errorf("invalid POA data_path format: %v", err)
	}

	return nil
}

// validateBlockMerkleRoot 验证区块 Merkle 根
func validateBlockMerkleRoot(block *Block) error {
	if block.TxRoot != "" {
		if _, err := base64.RawURLEncoding.DecodeString(block.TxRoot); err != nil {
			return fmt.Errorf("invalid tx_root format: %v", err)
		}

		if len(block.Txs) > 0 {
			calculatedRoot := calculateMerkleRoot(block.Txs)
			if calculatedRoot != block.TxRoot {
				return fmt.Errorf("tx_root mismatch: expected %s, got %s", block.TxRoot, calculatedRoot)
			}
		}
	}

	if block.HashListMerkle != "" {
		if _, err := base64.RawURLEncoding.DecodeString(block.HashListMerkle); err != nil {
			return fmt.Errorf("invalid hash_list_merkle format: %v", err)
		}
	}

	return nil
}

// calculateMerkleRoot 计算交易列表的 Merkle 根
func calculateMerkleRoot(txs []string) string {
	if len(txs) == 0 {
		return ""
	}

	if len(txs) == 1 {
		hash := sha256.Sum256([]byte(txs[0]))
		return base64.RawURLEncoding.EncodeToString(hash[:])
	}

	var hashes []string
	for _, tx := range txs {
		hash := sha256.Sum256([]byte(tx))
		hashes = append(hashes, base64.RawURLEncoding.EncodeToString(hash[:]))
	}

	for len(hashes) > 1 {
		if len(hashes)%2 != 0 {
			hashes = append(hashes, hashes[len(hashes)-1])
		}

		var newHashes []string
		for i := 0; i < len(hashes); i += 2 {
			combined := hashes[i] + hashes[i+1]
			hash := sha256.Sum256([]byte(combined))
			newHashes = append(newHashes, base64.RawURLEncoding.EncodeToString(hash[:]))
		}
		hashes = newHashes
	}

	return hashes[0]
}

// FetchBlockByHeight 通过高度获取区块
func FetchBlockByHeight(gateway string, height int64) (*Block, error) {
	url := fmt.Sprintf("%s/block/height/%d", strings.TrimRight(gateway, "/"), height)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch block: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status: %d", resp.StatusCode)
	}

	var block Block
	if err := json.NewDecoder(resp.Body).Decode(&block); err != nil {
		return nil, fmt.Errorf("failed to parse block JSON: %v", err)
	}

	return &block, nil
}

// FetchBlockByHash 通过哈希获取区块
func FetchBlockByHash(gateway string, hash string) (*Block, error) {
	url := fmt.Sprintf("%s/block/hash/%s", strings.TrimRight(gateway, "/"), hash)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch block: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status: %d", resp.StatusCode)
	}

	var block Block
	if err := json.NewDecoder(resp.Body).Decode(&block); err != nil {
		return nil, fmt.Errorf("failed to parse block JSON: %v", err)
	}

	return &block, nil
}

// FetchCurrentBlock 获取当前区块
func FetchCurrentBlock(gateway string) (*Block, error) {
	url := fmt.Sprintf("%s/current_block", strings.TrimRight(gateway, "/"))

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch current block: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status: %d", resp.StatusCode)
	}

	var block Block
	if err := json.NewDecoder(resp.Body).Decode(&block); err != nil {
		return nil, fmt.Errorf("failed to parse block JSON: %v", err)
	}

	return &block, nil
}

// FetchBlockHeader 仅获取区块头部（轻量级）
func FetchBlockHeader(gateway string, height int64) (*BlockHeader, error) {
	block, err := FetchBlockByHeight(gateway, height)
	if err != nil {
		return nil, err
	}

	return &BlockHeader{
		Height:        block.Height,
		Hash:          block.Hash,
		IndepHash:     block.IndepHash,
		PreviousBlock: block.PreviousBlock,
		Timestamp:     block.Timestamp,
		TxRoot:        block.TxRoot,
		Nonce:         block.Nonce,
		Diff:          block.Diff.String(),
	}, nil
}

// VerifyBlockLight 轻量验证区块（便捷函数）
func VerifyBlockLight(gateway string, height int64) (*BlockVerificationResult, error) {
	block, err := FetchBlockByHeight(gateway, height)
	if err != nil {
		return nil, err
	}

	parser := &BlockParser{
		block: block,
		header: &BlockHeader{
			Height:        block.Height,
			Hash:          block.Hash,
			IndepHash:     block.IndepHash,
			PreviousBlock: block.PreviousBlock,
			Timestamp:     block.Timestamp,
			TxRoot:        block.TxRoot,
			Nonce:         block.Nonce,
			Diff:          block.Diff.String(),
		},
	}

	return parser.VerifyLight()
}

// VerifyBlockFull 全量验证区块（便捷函数）
func VerifyBlockFull(gateway string, height int64) (*BlockVerificationResult, error) {
	block, err := FetchBlockByHeight(gateway, height)
	if err != nil {
		return nil, err
	}

	parser := &BlockParser{
		block: block,
		header: &BlockHeader{
			Height:        block.Height,
			Hash:          block.Hash,
			IndepHash:     block.IndepHash,
			PreviousBlock: block.PreviousBlock,
			Timestamp:     block.Timestamp,
			TxRoot:        block.TxRoot,
			Nonce:         block.Nonce,
			Diff:          block.Diff.String(),
		},
	}

	return parser.VerifyFull()
}

// GetTransactionIDs 获取区块中的所有交易 ID
func (p *BlockParser) GetTransactionIDs() ([]string, error) {
	if p.block == nil {
		return nil, errors.New("block not parsed")
	}
	return p.block.Txs, nil
}

// GetTransactionCount 获取区块中的交易数量
func (p *BlockParser) GetTransactionCount() (int, error) {
	if p.block == nil {
		return 0, errors.New("block not parsed")
	}
	return len(p.block.Txs), nil
}

// GetPOA 获取区块的访问证明
func (p *BlockParser) GetPOA() (*ProofOfAccess, error) {
	if p.block == nil {
		return nil, errors.New("block not parsed")
	}
	return p.block.POA, nil
}

// GetRewardAddr 获取区块的奖励地址
func (p *BlockParser) GetRewardAddr() (string, error) {
	if p.block == nil {
		return "", errors.New("block not parsed")
	}
	return p.block.RewardAddr, nil
}

// GetWeaveSize 获取 Weave 数据大小
func (p *BlockParser) GetWeaveSize() (int64, error) {
	if p.block == nil {
		return 0, errors.New("block not parsed")
	}
	return strconv.ParseInt(p.block.WeaveSize.String(), 10, 64)
}

// GetBlockSize 获取区块大小
func (p *BlockParser) GetBlockSize() (int64, error) {
	if p.block == nil {
		return 0, errors.New("block not parsed")
	}
	return strconv.ParseInt(p.block.BlockSize.String(), 10, 64)
}

// GetCumulativeDiff 获取累计难度
func (p *BlockParser) GetCumulativeDiff() (string, error) {
	if p.block == nil {
		return "", errors.New("block not parsed")
	}
	return p.block.CumulativeDiff.String(), nil
}

// FetchTransactionTags 轻量获取单个交易的 tags
// 使用 /tx/[id]/tags 端点，仅获取 tags 字段而不获取完整交易数据
func FetchTransactionTags(gateway, txID string) ([]Tag, error) {
	client := &http.Client{Timeout: defaultTimeout}
	url := fmt.Sprintf("%s/tx/%s/tags", gateway, txID)

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch transaction tags: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status: %d", resp.StatusCode)
	}

	var tags []Tag
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return nil, fmt.Errorf("failed to parse tags JSON: %v", err)
	}

	return tags, nil
}

// FetchBlockTransactionTags 轻量获取区块内所有交易的 tags
// 并发获取每个交易的 tags，返回交易 ID 到 tags 的映射
func FetchBlockTransactionTags(gateway string, height int64) (map[string][]Tag, error) {
	block, err := FetchBlockByHeight(gateway, height)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch block: %v", err)
	}

	if len(block.Txs) == 0 {
		return make(map[string][]Tag), nil
	}

	result := make(map[string][]Tag)
	var mu sync.Mutex
	errChan := make(chan error, len(block.Txs))

	// 并发获取所有交易的 tags
	for _, txID := range block.Txs {
		go func(id string) {
			tags, err := FetchTransactionTags(gateway, id)
			if err != nil {
				errChan <- fmt.Errorf("tx %s: %v", id, err)
				return
			}
			mu.Lock()
			result[id] = tags
			mu.Unlock()
			errChan <- nil
		}(txID)
	}

	// 收集所有结果
	var errs []string
	for i := 0; i < len(block.Txs); i++ {
		if err := <-errChan; err != nil {
			errs = append(errs, err.Error())
		}
	}

	if len(errs) > 0 {
		return result, fmt.Errorf("some transactions failed: %v", errs)
	}

	return result, nil
}

// FetchBlockTransactionTagsLight 轻量获取区块内指定交易的 tags
// 仅获取指定的交易 IDs 的 tags，而不是所有交易
func FetchBlockTransactionTagsLight(gateway string, txIDs []string) (map[string][]Tag, error) {
	result := make(map[string][]Tag)
	var mu sync.Mutex
	errChan := make(chan error, len(txIDs))

	// 并发获取指定交易的 tags
	for _, txID := range txIDs {
		go func(id string) {
			tags, err := FetchTransactionTags(gateway, id)
			if err != nil {
				errChan <- fmt.Errorf("tx %s: %v", id, err)
				return
			}
			mu.Lock()
			result[id] = tags
			mu.Unlock()
			errChan <- nil
		}(txID)
	}

	// 收集所有结果
	var errs []string
	for i := 0; i < len(txIDs); i++ {
		if err := <-errChan; err != nil {
			errs = append(errs, err.Error())
		}
	}

	if len(errs) > 0 {
		return result, fmt.Errorf("some transactions failed: %v", errs)
	}

	return result, nil
}

// GetBlockTransactionCount 获取区块内的交易数量
func GetBlockTransactionCount(gateway string, height int64) (int, error) {
	block, err := FetchBlockByHeight(gateway, height)
	if err != nil {
		return 0, err
	}
	return len(block.Txs), nil
}

// GetBlockTransactionIDs 获取区块内的所有交易 ID
func GetBlockTransactionIDs(gateway string, height int64) ([]string, error) {
	block, err := FetchBlockByHeight(gateway, height)
	if err != nil {
		return nil, err
	}
	return block.Txs, nil
}
