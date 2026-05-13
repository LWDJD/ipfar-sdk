// Package metadata 提供 IPFAR 元数据 JSON 的解析与验证功能
// 规范参考: ipfar-specs/V1/数据结构规范.md §2
package metadata

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// 元数据 JSON 版本常量
const (
	Version1 = 1

	// MethodRaw    标准 Arweave 交易
	MethodRaw = "raw"
	// MethodBundle ANS-104 Bundle
	MethodBundle = "bundle"

	// PoWThreshold 100 MiB：小于此值的文件需要 PoW
	PoWThreshold = 100 * 1024 * 1024
)

// 错误定义
var (
	ErrInvalidJSON        = errors.New("invalid metadata JSON")
	ErrMissingField       = errors.New("missing required field")
	ErrInvalidVersion     = errors.New("invalid version: must be 1")
	ErrInvalidMethod      = errors.New("invalid method: must be 'raw' or 'bundle'")
	ErrInvalidRootCID     = errors.New("invalid root_cid: must be a non-empty Base32 CID string")
	ErrInvalidDataTXID    = errors.New("invalid data_txid: must be a non-empty Arweave transaction ID")
	ErrInvalidDataHeight  = errors.New("invalid data_height: must be a non-negative integer")
	ErrInvalidDataSize    = errors.New("invalid data_size: must be a positive integer")
	ErrMissingPoW         = errors.New("missing pow: required for files smaller than 100 MiB")
	ErrMissingPowAlg      = errors.New("missing pow_alg: required for files smaller than 100 MiB")
	ErrInvalidReference   = errors.New("invalid reference format")
	ErrInvalidContentType = errors.New("invalid content_type")
	ErrInvalidOriginalName = errors.New("invalid original_name")
)

// ReferenceEntry 引用条目：一个被引用的 Arweave 交易
// 格式：{"txid": {"height": 1913001, "cids": ["cid1", "cid2"]}}
type ReferenceEntry struct {
	Height int      `json:"height"` // 区块高度
	CIDs   []string `json:"cids"`   // CID 列表
}

// ReferenceMap 引用映射：key = Arweave 交易 ID，value = 引用条目
type ReferenceMap map[string]ReferenceEntry

// Metadata IPFAR 元数据结构
// 规范参考: 数据结构规范.md §2.2 JSON 结构
type Metadata struct {
	Version      int            `json:"version"`                 // 必填：元数据格式版本（当前为 1）
	Method       string         `json:"method"`                  // 必填：上传方式 "raw" / "bundle"
	RootCID      string         `json:"root_cid"`                // 必填：根 CID（Base32）
	DataTXID     string         `json:"data_txid"`               // 必填：主 CAR 文件 Arweave TX ID
	DataHeight   int            `json:"data_height"`             // 必填：data_txid 所属区块高度
	DataSize     int            `json:"data_size"`               // 必填：原始数据大小（字节）
	Reference    *ReferenceMap  `json:"reference,omitempty"`     // 可选：引用映射（去重/分块）
	ContentType  string         `json:"content_type,omitempty"`  // 可选：MIME 类型
	OriginalName string         `json:"original_name,omitempty"` // 可选：原始文件名
	PoW          string         `json:"pow,omitempty"`           // 条件必填：PoW salt（< 100 MiB 时必填）
	PoWAlg       string         `json:"pow_alg,omitempty"`       // 条件必填：PoW 算法标识
}

// ParseJSON 从 JSON 字节数组解析元数据
// 输入为 Base64URL 解码后的 JSON 字节
func ParseJSON(data []byte) (*Metadata, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty data", ErrInvalidJSON)
	}

	var meta Metadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}

	return &meta, nil
}

// ParseFromBase64URL 从 Base64URL 编码的字符串解析元数据
// 先解码 Base64URL，再解析 JSON
func ParseFromBase64URL(encoded string) (*Metadata, error) {
	if encoded == "" {
		return nil, fmt.Errorf("%w: empty Base64URL string", ErrInvalidJSON)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		// 尝试标准 Base64（带填充）
		decoded, err = base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to decode Base64URL: %v", ErrInvalidJSON, err)
		}
	}

	return ParseJSON(decoded)
}

// Validate 验证元数据的完整性和合法性
// 规范参考: 数据结构规范.md §2.2 字段表
func (m *Metadata) Validate() error {
	// 1. version：必填，必须为 1
	if m.Version == 0 {
		return fmt.Errorf("%w: version", ErrMissingField)
	}
	if m.Version != Version1 {
		return fmt.Errorf("%w: got %d", ErrInvalidVersion, m.Version)
	}

	// 2. method：必填，必须为 "raw" 或 "bundle"
	if m.Method == "" {
		return fmt.Errorf("%w: method", ErrMissingField)
	}
	if m.Method != MethodRaw && m.Method != MethodBundle {
		return fmt.Errorf("%w: got %q", ErrInvalidMethod, m.Method)
	}

	// 3. root_cid：必填，非空字符串
	if m.RootCID == "" {
		return fmt.Errorf("%w: root_cid", ErrMissingField)
	}
	if !isValidCIDString(m.RootCID) {
		return fmt.Errorf("%w: %q", ErrInvalidRootCID, m.RootCID)
	}

	// 4. data_txid：必填，非空字符串
	if m.DataTXID == "" {
		return fmt.Errorf("%w: data_txid", ErrMissingField)
	}
	if !isValidTXIDString(m.DataTXID) {
		return fmt.Errorf("%w: %q", ErrInvalidDataTXID, m.DataTXID)
	}

	// 5. data_height：必填，非负整数
	if m.DataHeight < 0 {
		return fmt.Errorf("%w: got %d", ErrInvalidDataHeight, m.DataHeight)
	}
	// data_height 为 0 时也视为有效（创世区块或未知高度）

	// 6. data_size：必填，正整数
	if m.DataSize <= 0 {
		return fmt.Errorf("%w: got %d", ErrInvalidDataSize, m.DataSize)
	}

	// 7. reference：可选，但若存在则验证结构
	if m.Reference != nil {
		if err := validateReference(m.Reference); err != nil {
			return err
		}
	}

	// 8. pow / pow_alg：条件必填（data_size < 100 MiB 时必填）
	if int64(m.DataSize) < PoWThreshold {
		if m.PoW == "" {
			return ErrMissingPoW
		}
		if m.PoWAlg == "" {
			return ErrMissingPowAlg
		}
	}

	// 9. content_type：可选，若存在应为非空字符串
	// （规范不强制校验 MIME 格式）

	// 10. original_name：可选，若存在应为非空字符串

	return nil
}

// NeedsPoW 判断此元数据对应的文件是否需要 PoW
func (m *Metadata) NeedsPoW() bool {
	return int64(m.DataSize) < PoWThreshold
}

// HasReference 判断是否包含引用
func (m *Metadata) HasReference() bool {
	return m.Reference != nil && len(*m.Reference) > 0
}

// ToJSON 序列化为 JSON 字节数组
func (m *Metadata) ToJSON() ([]byte, error) {
	return json.Marshal(m)
}

// ToBase64URL 序列化为 JSON 并 Base64URL 编码
func (m *Metadata) ToBase64URL() (string, error) {
	jsonBytes, err := m.ToJSON()
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(jsonBytes), nil
}

// validateReference 验证 reference 字段的格式
// 规范参考: 数据结构规范.md §4.2 引用格式
func validateReference(ref *ReferenceMap) error {
	if ref == nil || len(*ref) == 0 {
		return nil
	}

	for txid, entry := range *ref {
		// txid 必须非空
		if txid == "" {
			return fmt.Errorf("%w: empty transaction ID key", ErrInvalidReference)
		}

		// height 应 >= 0
		if entry.Height < 0 {
			return fmt.Errorf("%w: negative height %d for txid %q", ErrInvalidReference, entry.Height, txid)
		}

		// cids 不能为空
		if len(entry.CIDs) == 0 {
			return fmt.Errorf("%w: empty cids list for txid %q", ErrInvalidReference, txid)
		}

		// 每个 cid 应非空
		for i, cid := range entry.CIDs {
			if cid == "" {
				return fmt.Errorf("%w: empty cid at index %d for txid %q", ErrInvalidReference, i, txid)
			}
		}
	}

	return nil
}

// isValidCIDString 简单校验 CID 字符串格式
// CID v1 Base32 通常以 "b" 开头（Base32 lowercase）
func isValidCIDString(cid string) bool {
	if len(cid) == 0 {
		return false
	}
	// Base32 CID 通常长度在 46-62 字符之间
	if len(cid) < 10 || len(cid) > 512 {
		return false
	}
	// 只允许 Base32 字符集 [a-z2-7] 或 CID v0 的 Base58 [1-9A-HJ-NP-Za-km-z]
	// 这里做宽松校验
	for _, c := range cid {
		if !isCIDChar(c) {
			return false
		}
	}
	return true
}

// isCIDChar 检查字符是否为合法 CID 字符
// 支持 Base32 (lowercase) 和 Base58
func isCIDChar(c rune) bool {
	if c >= 'a' && c <= 'z' {
		return true
	}
	if c >= 'A' && c <= 'Z' {
		return true
	}
	if c >= '0' && c <= '9' {
		return true
	}
	return false
}

// isValidTXIDString 简单校验 Arweave 交易 ID 字符串
// Arweave TX ID 是 Base64URL 编码的 256-bit SHA-256 哈希（43 字符，无填充）
func isValidTXIDString(txid string) bool {
	if len(txid) == 0 {
		return false
	}
	// Base64URL TX ID 通常 43 字符
	if len(txid) < 10 || len(txid) > 128 {
		return false
	}
	// 宽松校验：允许 Base64URL 字符集
	for _, c := range txid {
		if !isBase64URLChar(c) {
			return false
		}
	}
	return true
}

// isBase64URLChar 检查字符是否为合法 Base64URL 字符
func isBase64URLChar(c rune) bool {
	if c >= 'a' && c <= 'z' {
		return true
	}
	if c >= 'A' && c <= 'Z' {
		return true
	}
	if c >= '0' && c <= '9' {
		return true
	}
	if c == '-' || c == '_' {
		return true
	}
	return false
}

// ParseAndValidate 便捷函数：解析并验证元数据 JSON
func ParseAndValidate(data []byte) (*Metadata, error) {
	meta, err := ParseJSON(data)
	if err != nil {
		return nil, err
	}
	if err := meta.Validate(); err != nil {
		return nil, err
	}
	return meta, nil
}

// ParseAndValidateBase64URL 便捷函数：从 Base64URL 字符串解析并验证
func ParseAndValidateBase64URL(encoded string) (*Metadata, error) {
	meta, err := ParseFromBase64URL(encoded)
	if err != nil {
		return nil, err
	}
	if err := meta.Validate(); err != nil {
		return nil, err
	}
	return meta, nil
}

// ValidateTags 验证 Arweave Transaction Tags 是否符合 IPFAR 规范
// 规范参考: 数据结构规范.md §1
//
// 根据 Content-Type 和 IPFAR-Type 判断 tag 类型后进行验证：
//   - 通用 Tags（所有桥交易必填）: Protocol, Protocol-Version
//   - 元数据 Tags: IPFAR-Type: meta, Root-CID, Content-Type, Data-TXID
//   - CAR 文件 Tags: Root-CID, Data-Size, Content-Type
func ValidateTags(tags []Tag) error {
	if len(tags) == 0 {
		return errors.New("tags must not be empty")
	}

	tagMap := make(map[string]string)
	for _, tag := range tags {
		tagMap[tag.Name] = tag.Value
	}

	// 通用 Tags（所有桥交易必填）
	protocol, ok := tagMap["Protocol"]
	if !ok || protocol == "" {
		return fmt.Errorf("%w: Protocol", ErrMissingField)
	}
	if protocol != "IPFS-Arweave-Bridge" {
		return fmt.Errorf("invalid Protocol tag: expected 'IPFS-Arweave-Bridge', got %q", protocol)
	}

	protocolVersion, ok := tagMap["Protocol-Version"]
	if !ok || protocolVersion == "" {
		return fmt.Errorf("%w: Protocol-Version", ErrMissingField)
	}
	if protocolVersion != "1" {
		return fmt.Errorf("invalid Protocol-Version tag: expected '1', got %q", protocolVersion)
	}

	// 根据 Content-Type 和 IPFAR-Type 分类验证
	contentType, hasContentType := tagMap["Content-Type"]
	ipfarType, hasIPFARType := tagMap["IPFAR-Type"]

	if hasIPFARType && ipfarType == "meta" {
		// 元数据 Tags 验证
		return validateMetaTags(tagMap)
	}

	if hasContentType && contentType == "application/vnd.ipld.car" {
		// CAR 文件 Tags 验证
		return validateCARTags(tagMap)
	}

	// 如果既不是 meta 也不是 CAR，但有通用 Tags，基本合法
	return nil
}

// validateMetaTags 验证元数据交易 Tags
func validateMetaTags(tagMap map[string]string) error {
	// Content-Type 必须是 application/json
	contentType, ok := tagMap["Content-Type"]
	if !ok || contentType != "application/json" {
		return fmt.Errorf("metadata Content-Type must be 'application/json', got %q", contentType)
	}

	// IPFAR-Type 必须是 meta
	ipfarType, ok := tagMap["IPFAR-Type"]
	if !ok || ipfarType != "meta" {
		return fmt.Errorf("metadata IPFAR-Type must be 'meta', got %q", ipfarType)
	}

	// Root-CID 必填
	rootCID, ok := tagMap["Root-CID"]
	if !ok || rootCID == "" {
		return fmt.Errorf("%w: Root-CID", ErrMissingField)
	}

	// Data-TXID 必填
	dataTXID, ok := tagMap["Data-TXID"]
	if !ok || dataTXID == "" {
		return fmt.Errorf("%w: Data-TXID", ErrMissingField)
	}

	return nil
}

// validateCARTags 验证 CAR 文件交易 Tags
func validateCARTags(tagMap map[string]string) error {
	// Content-Type 必须是 application/vnd.ipld.car
	contentType, ok := tagMap["Content-Type"]
	if !ok || contentType != "application/vnd.ipld.car" {
		return fmt.Errorf("CAR Content-Type must be 'application/vnd.ipld.car', got %q", contentType)
	}

	// Root-CID 必填
	rootCID, ok := tagMap["Root-CID"]
	if !ok || rootCID == "" {
		return fmt.Errorf("%w: Root-CID", ErrMissingField)
	}

	// Data-Size 必填
	dataSize, ok := tagMap["Data-Size"]
	if !ok || dataSize == "" {
		return fmt.Errorf("%w: Data-Size", ErrMissingField)
	}

	return nil
}

// Tag 表示 Arweave Transaction Tag 键值对
type Tag struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// TagSlice 方便构造 Tag 列表
type TagSlice []Tag

// ToMap 将 Tag 切片转换为 map
func (ts TagSlice) ToMap() map[string]string {
	m := make(map[string]string)
	for _, t := range ts {
		m[t.Name] = t.Value
	}
	return m
}

// BuildMetaTags 构建元数据交易所需的完整 Tags
func BuildMetaTags(rootCID, dataTXID string) []Tag {
	return []Tag{
		{Name: "Protocol", Value: "IPFS-Arweave-Bridge"},
		{Name: "Protocol-Version", Value: "1"},
		{Name: "IPFAR-Type", Value: "meta"},
		{Name: "Root-CID", Value: rootCID},
		{Name: "Content-Type", Value: "application/json"},
		{Name: "Data-TXID", Value: dataTXID},
	}
}

// BuildCARTags 构建 CAR 文件交易所需的完整 Tags
func BuildCARTags(rootCID string, dataSize int64) []Tag {
	return []Tag{
		{Name: "Protocol", Value: "IPFS-Arweave-Bridge"},
		{Name: "Protocol-Version", Value: "1"},
		{Name: "Root-CID", Value: rootCID},
		{Name: "Data-Size", Value: fmt.Sprintf("%d", dataSize)},
		{Name: "Content-Type", Value: "application/vnd.ipld.car"},
	}
}

// CleanCID 清理 CID 字符串（去除多余空格和引号）
func CleanCID(cid string) string {
	return strings.Trim(strings.TrimSpace(cid), "\"")
}
