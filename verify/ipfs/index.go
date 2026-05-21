// Package ipfs 提供 IPFS CAR 文件的索引解析与完整性验证
// CARv2 Index 格式参考: https://ipld.io/specs/transport/car/carv2/
package ipfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-varint"
)

// IndexEntry CARv2 索引条目
// 将 CID（或 multihash）映射到数据段中的字节偏移量
type IndexEntry struct {
	CID    cid.Cid // 数据块的 CID
	Offset uint64  // 在 CAR 数据区中的字节偏移量（相对于 CAR 文件起始位置）
}

// IndexType 索引类型
type IndexType int

const (
	// IndexTypeUnknown 未知索引格式
	IndexTypeUnknown IndexType = 0
	// IndexTypeSorted 排序 multihash 索引 (0x0400)
	IndexTypeSorted IndexType = 0x0400
	// IndexTypeMultihash 未排序 multihash 索引
	IndexTypeMultihash IndexType = 0x0401
	// IndexTypeCID CID 索引（完整 CID 作为键）
	IndexTypeCID IndexType = 0x0402
)

// 索引相关错误定义
var (
	ErrEmptyIndex         = errors.New("index section is empty")
	ErrInvalidIndexFormat = errors.New("invalid index format")
	ErrIndexEntryInvalid  = errors.New("index entry references invalid data")
	ErrIndexOffsetBounds  = errors.New("index entry offset out of bounds")
	ErrIndexContentMismatch = errors.New("index content does not match data blocks")
)

// ParseIndex 解析 CARv2 索引段
// 返回索引条目列表
func (p *CarParser) ParseIndex() ([]IndexEntry, error) {
	info, err := p.ParseInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to parse CAR info: %v", err)
	}

	if info.Version != 2 {
		return nil, fmt.Errorf("index only available for CARv2 files")
	}

	if !info.HasIndex {
		return nil, ErrIndexNotFound
	}

	if info.IndexSize == 0 {
		return nil, ErrEmptyIndex
	}

	// 读取索引段数据
	indexData := make([]byte, info.IndexSize)
	n, err := p.reader.ReadAt(indexData, int64(info.IndexOffset))
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to read index data: %v", err)
	}
	if uint64(n) < info.IndexSize {
		return nil, fmt.Errorf("short read: expected %d bytes, got %d", info.IndexSize, n)
	}

	// 检测索引类型并解析
	return p.parseIndexData(indexData)
}

// parseIndexData 解析索引数据为条目列表
//
// CARv2 索引格式规范:
//   索引段是一个连续的字节序列，包含多个索引条目。
//   每个条目 = varint(条目总长度) + varint(CID长度) + CID字节 + varint(偏移量)
//
// 支持的索引类型由 CARv2 头部的 Characteristics 字段指示:
//   - 0x0400: IndexSorted (multihash 排序索引)
//   - 0x0401: MultihashIndexSorted (multihash 索引，未排序)
//   对于完整 CID 索引，直接使用 CID 字节
func (p *CarParser) parseIndexData(data []byte) ([]IndexEntry, error) {
	if len(data) == 0 {
		return nil, ErrEmptyIndex
	}

	var entries []IndexEntry
	offset := 0

	for offset < len(data) {
		// 读取条目总长度
		entryLen, n, err := p.readVarint(data[offset:])
		if err != nil {
			// 尝试作为无条目长度前缀的原始格式解析
			break
		}
		offset += n

		if offset+int(entryLen) > len(data) {
			return nil, fmt.Errorf("%w: entry extends beyond index data", ErrInvalidIndexFormat)
		}

		entryData := data[offset : offset+int(entryLen)]
		entryOffset := offset
		offset += int(entryLen)

		// 从条目数据中读取 CID
		cidLen, n, err := p.readVarint(entryData)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to read CID length at offset %d: %v", ErrInvalidIndexFormat, entryOffset, err)
		}
		pos := n

		if pos+int(cidLen) > len(entryData) {
			return nil, fmt.Errorf("%w: CID extends beyond entry", ErrInvalidIndexFormat)
		}

		cidBytes := entryData[pos : pos+int(cidLen)]
		pos += int(cidLen)

		blockCID, err := cid.Cast(cidBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid CID at index entry %d: %v", ErrInvalidIndexFormat, len(entries), err)
		}

		// 读取偏移量
		blockOffset, _, err := p.readVarint(entryData[pos:])
		if err != nil {
			return nil, fmt.Errorf("%w: failed to read offset at entry %d: %v", ErrInvalidIndexFormat, len(entries), err)
		}

		entries = append(entries, IndexEntry{
			CID:    blockCID,
			Offset: blockOffset,
		})
	}

	// 如果上述带长度前缀的解析没有产生任何条目，尝试原始格式
	// 原始格式: 每条目 = varint(CID长度) + CID字节 + varint(偏移量)，无外长度前缀
	if len(entries) == 0 {
		entries, err := p.parseRawIndexData(data)
		if err != nil {
			return nil, err
		}
		if len(entries) > 0 {
			return entries, nil
		}
		return nil, ErrInvalidIndexFormat
	}

	return entries, nil
}

// parseRawIndexData 解析无外层长度前缀的原始索引格式
// 格式: varint(CID长度) + CID字节 + varint(偏移量)
func (p *CarParser) parseRawIndexData(data []byte) ([]IndexEntry, error) {
	var entries []IndexEntry
	offset := 0

	for offset < len(data) {
		// 读取 CID 长度
		cidLen, n, err := p.readVarint(data[offset:])
		if err != nil {
			if offset == 0 {
				return nil, fmt.Errorf("%w: cannot parse index data", ErrInvalidIndexFormat)
			}
			break
		}
		offset += n

		if cidLen == 0 || offset+int(cidLen) > len(data) {
			break
		}

		cidBytes := data[offset : offset+int(cidLen)]
		offset += int(cidLen)

		blockCID, err := cid.Cast(cidBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid CID in raw index: %v", ErrInvalidIndexFormat, err)
		}

		// 读取偏移量
		blockOffset, n, err := p.readVarint(data[offset:])
		if err != nil {
			return nil, fmt.Errorf("%w: failed to read offset: %v", ErrInvalidIndexFormat, err)
		}
		offset += n

		entries = append(entries, IndexEntry{
			CID:    blockCID,
			Offset: blockOffset,
		})
	}

	return entries, nil
}

// readVarint 从字节切片读取 varint
// 返回: 值, 消耗的字节数, 错误
func (p *CarParser) readVarint(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, io.EOF
	}
	value, n, err := varint.FromUvarint(data)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid varint: %v", err)
	}
	if n <= 0 {
		return 0, 0, fmt.Errorf("invalid varint: zero-length read")
	}
	return value, n, nil
}

// ValidateIndexExistence 检查 CARv2 文件是否包含索引（仅存在性检查，不校验内容）
//
// 规范 §3.4：Index 存在性检查始终强制执行，不受 verify_index 配置影响。
// 对于 CARv1 文件，始终返回 nil（CARv1 不需要索引）。
// 对于 CARv2 文件，若缺少索引则返回 ErrIndexNotFound。
func (p *CarParser) ValidateIndexExistence() error {
	info, err := p.ParseInfo()
	if err != nil {
		return err
	}

	// CARv1 不需要索引
	if info.Version != 2 {
		return nil
	}

	if !info.HasIndex {
		return ErrIndexNotFound
	}

	return nil
}

// ValidateIndexContent 验证索引内容的完整性
//
// 检查:
//  1. 索引可解析
//  2. 每个索引条目的偏移量在有效范围内
//  3. 每个索引条目指向的块 CID 与索引中的 CID 一致
//  4. 数据段中的所有块都在索引中有对应条目（如果索引存在）
func (p *CarParser) ValidateIndexContent() error {
	info, err := p.ParseInfo()
	if err != nil {
		return err
	}

	if info.Version != 2 {
		return fmt.Errorf("index validation only supported for CARv2")
	}

	if !info.HasIndex {
		return ErrIndexNotFound
	}

	// 1. 解析索引
	entries, err := p.ParseIndex()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrIndexContentMismatch, err)
	}

	if len(entries) == 0 {
		return ErrEmptyIndex
	}

	// 2. 验证每个索引条目
	for i, entry := range entries {
		// 检查偏移量是否在文件有效范围内
		if entry.Offset > uint64(p.fileSize) {
			return fmt.Errorf("%w: entry %d (CID=%s) offset %d exceeds file size %d",
				ErrIndexOffsetBounds, i, entry.CID.String(), entry.Offset, p.fileSize)
		}

		// 检查条目指向的位置是否包含正确的 CID
		if err := p.validateEntryAtOffset(entry, info); err != nil {
			return fmt.Errorf("%w: entry %d (CID=%s): %v", ErrIndexEntryInvalid, i, entry.CID.String(), err)
		}
	}

	return nil
}

// validateEntryAtOffset 验证索引条目指向的偏移量处的块是否匹配
func (p *CarParser) validateEntryAtOffset(entry IndexEntry, info *CarInfo) error {
	// 读取该偏移量处的 section length
	sectionLen, err := p.readVarintAt(int64(entry.Offset))
	if err != nil {
		return fmt.Errorf("failed to read section length at offset %d: %v", entry.Offset, err)
	}

	if sectionLen == 0 {
		return fmt.Errorf("zero-length section at offset %d", entry.Offset)
	}

	// 读取 CID
	cidOffset := int64(entry.Offset) + 1
	cidBuf := make([]byte, sectionLen)
	n, err := p.reader.ReadAt(cidBuf, cidOffset)
	if err != nil {
		return fmt.Errorf("failed to read block at offset %d: %v", entry.Offset, err)
	}
	if n < 1 {
		return fmt.Errorf("incomplete block at offset %d", entry.Offset)
	}

	_, actualCID, err := cid.CidFromBytes(cidBuf[:n])
	if err != nil {
		return fmt.Errorf("invalid CID at offset %d: %v", entry.Offset, err)
	}

	// 比对 CID
	if !actualCID.Equals(entry.CID) {
		return fmt.Errorf("CID mismatch at offset %d: index says %s, found %s",
			entry.Offset, entry.CID.String(), actualCID.String())
	}

	return nil
}

// ValidateIndexCrossCheck 交叉验证索引与数据段
// 确保数据段中的每个块都在索引中有对应条目
func (p *CarParser) ValidateIndexCrossCheck() error {
	info, err := p.ParseInfo()
	if err != nil {
		return err
	}

	if info.Version != 2 || !info.HasIndex {
		return nil // 无索引不验证
	}

	entries, err := p.ParseIndex()
	if err != nil {
		return err
	}

	// 构建偏移量到 CID 的映射
	offsetToCID := make(map[uint64]cid.Cid)
	for _, entry := range entries {
		offsetToCID[entry.Offset] = entry.CID
	}

	// 遍历数据段中的所有块，检查是否在索引中
	offset := int64(info.DataOffset)
	endOffset := int64(info.DataOffset + info.DataSize)

	for offset < endOffset {
		sectionLen, err := p.readVarintAt(offset)
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("cross-check failed at offset %d: %v", offset, err)
		}

		if sectionLen == 0 {
			break
		}

		cidOffset := offset + 1
		cidBuf := make([]byte, sectionLen)
		n, err := p.reader.ReadAt(cidBuf, cidOffset)
		if err != nil && err != io.EOF {
			return fmt.Errorf("cross-check read failed at offset %d: %v", offset, err)
		}

		_, blockCID, err := cid.CidFromBytes(cidBuf[:n])
		if err != nil {
			return fmt.Errorf("cross-check invalid CID at offset %d: %v", offset, err)
		}

		// 检查该偏移量是否在索引中
		sourceOffset := uint64(offset)
		indexedCID, found := offsetToCID[sourceOffset]
		if !found {
			return fmt.Errorf("%w: block at offset %d (CID=%s) not found in index",
				ErrIndexContentMismatch, sourceOffset, blockCID.String())
		}
		if !indexedCID.Equals(blockCID) {
			return fmt.Errorf("%w: index mismatch at offset %d: index says %s, data says %s",
				ErrIndexContentMismatch, sourceOffset, indexedCID.String(), blockCID.String())
		}

		cidLen := blockCID.ByteLen()
		dataLen := sectionLen - uint64(cidLen)
		offset = cidOffset + int64(cidLen) + int64(dataLen)
	}

	return nil
}

// GetIndexType 获取索引类型
func (p *CarParser) GetIndexType() (IndexType, error) {
	info, err := p.ParseInfo()
	if err != nil {
		return IndexTypeUnknown, err
	}

	if info.Version != 2 {
		return IndexTypeUnknown, nil
	}

	// 从 Characteristics 字段读取索引类型
	// Characteristics[8:10] 包含索引编解码器标识
	if len(info.Roots) >= 0 {
		// 从 CARv2 头部读取
		buf := make([]byte, 4+48) // pragma + header
		n, err := p.reader.ReadAt(buf, 0)
		if err != nil {
			return IndexTypeUnknown, err
		}
		if n < 20 {
			return IndexTypeUnknown, fmt.Errorf("file too small for CARv2 header")
		}

		// Characteristics 在偏移 4+16 处，占 2 字节（大端序）
		indexCodec := binary.BigEndian.Uint16(buf[4+24 : 4+26])
		switch indexCodec {
		case 0x0400:
			return IndexTypeSorted, nil
		case 0x0401:
			return IndexTypeMultihash, nil
		case 0x0402:
			return IndexTypeCID, nil
		default:
			return IndexTypeUnknown, nil
		}
	}

	return IndexTypeUnknown, nil
}

// BuildIndexBuilder 辅助类型：用于构建 CARv2 索引（测试用）
type IndexBuilder struct {
	entries []IndexEntry
}

// NewIndexBuilder 创建索引构建器
func NewIndexBuilder() *IndexBuilder {
	return &IndexBuilder{
		entries: make([]IndexEntry, 0),
	}
}

// AddEntry 添加索引条目
func (ib *IndexBuilder) AddEntry(c cid.Cid, offset uint64) {
	ib.entries = append(ib.entries, IndexEntry{CID: c, Offset: offset})
}

// Build 构建索引字节数据（带外层长度前缀格式）
// 格式: 每条目 = varint(条目长度) + varint(CID字节数) + CID字节 + varint(偏移量)
func (ib *IndexBuilder) Build() []byte {
	var buf bytes.Buffer

	for _, entry := range ib.entries {
		cidBytes := entry.CID.Bytes()

		// 计算条目内容: varint(cidLen) + cidBytes + varint(offset)
		entryContent := make([]byte, 0)
		entryContent = append(entryContent, varint.ToUvarint(uint64(len(cidBytes)))...)
		entryContent = append(entryContent, cidBytes...)
		entryContent = append(entryContent, varint.ToUvarint(entry.Offset)...)

		// 写入外层长度前缀
		buf.Write(varint.ToUvarint(uint64(len(entryContent))))
		buf.Write(entryContent)
	}

	return buf.Bytes()
}

// BuildRaw 构建原始格式索引（无外层长度前缀）
func (ib *IndexBuilder) BuildRaw() []byte {
	var buf bytes.Buffer

	for _, entry := range ib.entries {
		cidBytes := entry.CID.Bytes()
		buf.Write(varint.ToUvarint(uint64(len(cidBytes))))
		buf.Write(cidBytes)
		buf.Write(varint.ToUvarint(entry.Offset))
	}

	return buf.Bytes()
}

// EntryCount 返回索引条目数量
func (ib *IndexBuilder) EntryCount() int {
	return len(ib.entries)
}
