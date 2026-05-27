// Package ipfs 提供 IPFS CAR 文件的索引解析与完整性验证
// 内部使用 go-car/v2 标准库的 index 子包。
package ipfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	carindex "github.com/ipld/go-car/v2/index"
	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
	"github.com/multiformats/go-varint"
)

// IndexEntry CARv2 索引条目
// 将 CID 映射到数据段中的字节偏移量
type IndexEntry struct {
	CID    cid.Cid // 数据块的 CID
	Offset uint64  // 在 CAR 数据区中的字节偏移量（相对于 CAR 文件起始位置）
}

// IndexType 索引类型
type IndexType int

const (
	// IndexTypeUnknown 未知索引格式
	IndexTypeUnknown IndexType = 0
	// IndexTypeSorted 排序 CID 索引
	IndexTypeSorted IndexType = 0x0400
	// IndexTypeMultihash 未排序 multihash 索引
	IndexTypeMultihash IndexType = 0x0401
	// IndexTypeCID CID 索引（完整 CID 作为键）
	IndexTypeCID IndexType = 0x0402
)

// 索引相关错误定义
var (
	ErrEmptyIndex          = errors.New("index section is empty")
	ErrInvalidIndexFormat  = errors.New("invalid index format")
	ErrIndexEntryInvalid   = errors.New("index entry references invalid data")
	ErrIndexOffsetBounds   = errors.New("index entry offset out of bounds")
	ErrIndexContentMismatch = errors.New("index content does not match data blocks")
)

// ParseIndex 解析 CARv2 索引段，返回索引条目列表
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
	indexData, err := p.readIndexData()
	if err != nil {
		return nil, err
	}

	// 使用 go-car/v2 的 index.ReadFrom 解析
	return parseIndexWithCarV2(indexData, info)
}

// parseIndexWithCarV2 使用 go-car/v2 解析索引并转换为 IndexEntry 列表
func parseIndexWithCarV2(data []byte, info *CarInfo) ([]IndexEntry, error) {
	idx, err := carindex.ReadFrom(bytes.NewReader(data))
	if err != nil {
		// 回退到自实现解析器
		return parseIndexDataFallbackAsEntries(data, info)
	}

	// 尝试通过 InsertionIndex 迭代所有条目
	if ii, ok := idx.(*carindex.InsertionIndex); ok {
		var entries []IndexEntry
		err := ii.ForEachCid(func(c cid.Cid, offset uint64) error {
			entries = append(entries, IndexEntry{
				CID:    c,
				Offset: offset,
			})
			return nil
		})
		if err != nil {
			return nil, err
		}
		return entries, nil
	}

	// 其他索引类型：通过已知 CID 查找（效率较低，回退到自实现）
	return parseIndexDataFallbackAsEntries(data, info)
}

// parseIndexDataFallbackAsEntries 自实现的索引解析（回退方案，返回 IndexEntry 列表）
func parseIndexDataFallbackAsEntries(data []byte, info *CarInfo) ([]IndexEntry, error) {
	return parseIndexDataRaw(data)
}

// =============================================================================
// carv2indexReadFrom parses index data using go-car/v2.
// Used by ParseIndexData standalone function in car.go.
// =============================================================================

func carv2indexReadFrom(r io.Reader) (carindex.Index, error) {
	return carindex.ReadFrom(r)
}

// carv2indexPopulateMap attempts to populate a map from an index by iterating all entries.
func carv2indexPopulateMap(idx carindex.Index, result map[string]uint64) error {
	// Try InsertionIndex first
	if ii, ok := idx.(*carindex.InsertionIndex); ok {
		return ii.ForEachCid(func(c cid.Cid, offset uint64) error {
			result[c.String()] = offset
			return nil
		})
	}

	// Try MultihashIndexSorted — not fully iterable, fall back.
	if _, ok := idx.(*carindex.MultihashIndexSorted); ok {
		// MultihashIndexSorted can iterate via GetAll with known CIDs,
		// but we don't have the CID list. Fall back.
		return fmt.Errorf("MultihashIndexSorted does not support full iteration")
	}

	return fmt.Errorf("index type does not support full iteration")
}

// =============================================================================
// Fallback index parser — handles standard CAR v2 index binary format
// =============================================================================

// parseIndexDataFallback parses index data into a CID→offset map (standalone).
func parseIndexDataFallback(data []byte) (map[string]uint64, error) {
	entries, err := parseIndexDataRaw(data)
	if err != nil {
		return nil, err
	}
	result := make(map[string]uint64, len(entries))
	for _, e := range entries {
		result[e.CID.String()] = e.Offset
	}
	return result, nil
}

// parseIndexDataRaw parses standard CAR v2 index binary data into entries.
// Supports CarIndexSorted (0x0400) and CarMultihashIndexSorted (0x0401).
func parseIndexDataRaw(data []byte) ([]IndexEntry, error) {
	if len(data) < 2 {
		return nil, ErrEmptyIndex
	}

	// Read multicodec code
	br := newBytesReader(data)
	codec, err := varint.ReadUvarint(br)
	if err != nil {
		return nil, fmt.Errorf("failed to read index codec: %w", err)
	}

	pos := br.pos

	switch codec {
	case 0x0400: // CarIndexSorted
		return parseIndexSorted(data[pos:])
	case 0x0401: // CarMultihashIndexSorted
		return parseMultihashIndexSorted(data[pos:])
	default:
		// Try legacy varint-delimited format
		return parseLegacyIndexFormat(data)
	}
}

// parseIndexSorted parses CarIndexSorted format index.
func parseIndexSorted(data []byte) ([]IndexEntry, error) {
	pos := 0

	if len(data) < 4 {
		return nil, fmt.Errorf("CarIndexSorted data too short")
	}
	bucketCount := int(binary.LittleEndian.Uint32(data[pos:]))
	pos += 4

	if bucketCount < 0 || bucketCount > 100000 {
		return nil, fmt.Errorf("index bucket count abnormal: %d", bucketCount)
	}

	var allEntries []IndexEntry

	for i := 0; i < bucketCount; i++ {
		if pos+12 > len(data) {
			return nil, fmt.Errorf("bucket %d data out of bounds", i)
		}

		width := binary.LittleEndian.Uint32(data[pos:])
		pos += 4
		dataLen := binary.LittleEndian.Uint64(data[pos:])
		pos += 8

		if width < 8 {
			return nil, fmt.Errorf("bucket %d width too small: %d", i, width)
		}

		if pos+int(dataLen) > len(data) {
			return nil, fmt.Errorf("bucket %d data length out of bounds", i)
		}

		digestLen := int(width) - 8
		entryCount := int(dataLen) / int(width)

		for j := 0; j < entryCount; j++ {
			entryStart := pos + j*int(width)
			digestEnd := entryStart + digestLen
			offsetEnd := digestEnd + 8

			digest := make([]byte, digestLen)
			copy(digest, data[entryStart:digestEnd])

			// Reconstruct multihash: SHA2-256 (code 0x12) + length 0x20 + digest
			mh, err := multihash.Encode(digest, multihash.SHA2_256)
			if err != nil {
				continue
			}

			offset := binary.LittleEndian.Uint64(data[digestEnd:offsetEnd])

			// Build CID v1 with raw codec
			c := cid.NewCidV1(cid.Raw, mh)

			allEntries = append(allEntries, IndexEntry{
				CID:    c,
				Offset: offset,
			})
		}

		pos += int(dataLen)
	}

	return allEntries, nil
}

// parseMultihashIndexSorted parses CarMultihashIndexSorted format index.
func parseMultihashIndexSorted(data []byte) ([]IndexEntry, error) {
	pos := 0

	if len(data) < 4 {
		return nil, fmt.Errorf("MultihashIndexSorted data too short")
	}
	bucketCount := int(binary.LittleEndian.Uint32(data[pos:]))
	pos += 4

	if bucketCount < 0 || bucketCount > 100000 {
		return nil, fmt.Errorf("index bucket count abnormal: %d", bucketCount)
	}

	var allEntries []IndexEntry

	for i := 0; i < bucketCount; i++ {
		if pos+8 > len(data) {
			return nil, fmt.Errorf("multihash bucket %d data out of bounds", i)
		}

		mhCode := binary.LittleEndian.Uint64(data[pos:])
		pos += 8

		entries, newPos, err := parseIndexSortedWithMHPos(data, pos, mhCode)
		if err != nil {
			return nil, fmt.Errorf("multihash bucket %d (code=%d) parse failed: %w", i, mhCode, err)
		}
		pos = newPos
		allEntries = append(allEntries, entries...)
	}

	return allEntries, nil
}

// parseIndexSortedWithMHPos parses multi-width index entries with multihash code.
func parseIndexSortedWithMHPos(data []byte, startPos int, mhCode uint64) ([]IndexEntry, int, error) {
	pos := startPos

	if pos+4 > len(data) {
		return nil, pos, fmt.Errorf("multiWidthIndex data too short")
	}
	bucketCount := int(binary.LittleEndian.Uint32(data[pos:]))
	pos += 4

	var allEntries []IndexEntry

	for i := 0; i < bucketCount; i++ {
		if pos+12 > len(data) {
			return nil, pos, fmt.Errorf("width bucket %d out of bounds", i)
		}

		width := binary.LittleEndian.Uint32(data[pos:])
		pos += 4
		dataLen := binary.LittleEndian.Uint64(data[pos:])
		pos += 8

		if width < 8 {
			return nil, pos, fmt.Errorf("width bucket %d width too small: %d", i, width)
		}

		if pos+int(dataLen) > len(data) {
			return nil, pos, fmt.Errorf("width bucket %d data out of bounds", i)
		}

		digestLen := int(width) - 8
		entryCount := int(dataLen) / int(width)

		for j := 0; j < entryCount; j++ {
			entryStart := pos + j*int(width)
			digestEnd := entryStart + digestLen
			offsetEnd := digestEnd + 8

			digest := make([]byte, digestLen)
			copy(digest, data[entryStart:digestEnd])

			mh, err := multihash.Encode(digest, mhCode)
			if err != nil {
				continue
			}

			offset := binary.LittleEndian.Uint64(data[digestEnd:offsetEnd])

			c := cid.NewCidV1(cid.Raw, mh)

			allEntries = append(allEntries, IndexEntry{
				CID:    c,
				Offset: offset,
			})
		}

		pos += int(dataLen)
	}

	return allEntries, pos, nil
}

// parseLegacyIndexFormat attempts to parse legacy varint-delimited index format.
func parseLegacyIndexFormat(data []byte) ([]IndexEntry, error) {
	var entries []IndexEntry
	offset := 0

	for offset < len(data) {
		cidLen, n, err := readVarintFromBytes(data[offset:])
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

		blockOffset, n, err := readVarintFromBytes(data[offset:])
		if err != nil {
			return nil, fmt.Errorf("%w: failed to read offset: %v", ErrInvalidIndexFormat, err)
		}
		offset += n

		entries = append(entries, IndexEntry{
			CID:    blockCID,
			Offset: blockOffset,
		})
	}

	if len(entries) == 0 {
		return nil, ErrInvalidIndexFormat
	}
	return entries, nil
}

// newBytesReader 创建 bytesReader（用于 varint 解析）
type bytesReader struct {
	data []byte
	pos  int
}

func newBytesReader(data []byte) *bytesReader {
	return &bytesReader{data: data, pos: 0}
}

func (r *bytesReader) ReadByte() (byte, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	b := r.data[r.pos]
	r.pos++
	return b, nil
}

func (r *bytesReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// =============================================================================
// Validation functions
// =============================================================================

// ValidateIndexExistence 检查 CARv2 文件是否包含索引
func (p *CarParser) ValidateIndexExistence() error {
	info, err := p.ParseInfo()
	if err != nil {
		return err
	}

	if info.Version != 2 {
		return nil // CARv1 doesn't need index
	}

	if !info.HasIndex {
		return ErrIndexNotFound
	}

	return nil
}

// ValidateIndexContent 验证索引内容的完整性
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

	entries, err := p.ParseIndex()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrIndexContentMismatch, err)
	}

	if len(entries) == 0 {
		return ErrEmptyIndex
	}

	for i, entry := range entries {
		if entry.Offset > uint64(p.fileSize) {
			return fmt.Errorf("%w: entry %d (CID=%s) offset %d exceeds file size %d",
				ErrIndexOffsetBounds, i, entry.CID.String(), entry.Offset, p.fileSize)
		}

		if err := p.validateEntryAtOffset(entry, info); err != nil {
			return fmt.Errorf("%w: entry %d (CID=%s): %v", ErrIndexEntryInvalid, i, entry.CID.String(), err)
		}
	}

	return nil
}

// validateEntryAtOffset 验证索引条目指向的偏移量处的块是否匹配
func (p *CarParser) validateEntryAtOffset(entry IndexEntry, info *CarInfo) error {
	sectionLen, varintSize, err := p.readVarintSizeAt(int64(entry.Offset))
	if err != nil {
		return fmt.Errorf("failed to read section length at offset %d: %v", entry.Offset, err)
	}

	if sectionLen == 0 {
		return fmt.Errorf("zero-length section at offset %d", entry.Offset)
	}

	cidOffset := int64(entry.Offset) + int64(varintSize)
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

	if !actualCID.Equals(entry.CID) {
		return fmt.Errorf("CID mismatch at offset %d: index says %s, found %s",
			entry.Offset, entry.CID.String(), actualCID.String())
	}

	return nil
}

// ValidateIndexCrossCheck 交叉验证索引与数据段
func (p *CarParser) ValidateIndexCrossCheck() error {
	info, err := p.ParseInfo()
	if err != nil {
		return err
	}

	if info.Version != 2 || !info.HasIndex {
		return nil
	}

	entries, err := p.ParseIndex()
	if err != nil {
		return err
	}

	offsetToCID := make(map[uint64]cid.Cid)
	for _, entry := range entries {
		offsetToCID[entry.Offset] = entry.CID
	}

	offset := int64(info.DataOffset)
	endOffset := int64(info.DataOffset + info.DataSize)

	for offset < endOffset {
		sectionLen, varintSize, err := p.readVarintSizeAt(offset)
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("cross-check failed at offset %d: %v", offset, err)
		}

		if sectionLen == 0 {
			break
		}

		cidOffset := offset + int64(varintSize)
		cidBuf := make([]byte, sectionLen)
		n, err := p.reader.ReadAt(cidBuf, cidOffset)
		if err != nil && err != io.EOF {
			return fmt.Errorf("cross-check read failed at offset %d: %v", offset, err)
		}

		_, blockCID, err := cid.CidFromBytes(cidBuf[:n])
		if err != nil {
			return fmt.Errorf("cross-check invalid CID at offset %d: %v", offset, err)
		}

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

	if p.carV2Reader != nil {
		// Use go-car/v2's Inspect to get the index codec
		stats, inspectErr := p.carV2Reader.Inspect(false)
		if inspectErr == nil {
			switch stats.IndexCodec {
			case 0x0400:
				return IndexTypeSorted, nil
			case 0x0401:
				return IndexTypeMultihash, nil
			default:
				return IndexTypeUnknown, nil
			}
		}
	}

	// Fallback: read index codec from raw index data
	indexData, err := p.readIndexData()
	if err != nil {
		return IndexTypeUnknown, err
	}
	if len(indexData) < 2 {
		return IndexTypeUnknown, nil
	}

	codec, _, err := readVarintFromBytes(indexData)
	if err != nil {
		return IndexTypeUnknown, err
	}

	switch codec {
	case 0x0400:
		return IndexTypeSorted, nil
	case 0x0401:
		return IndexTypeMultihash, nil
	default:
		return IndexTypeUnknown, nil
	}
}

// =============================================================================
// IndexBuilder — kept for backward compatibility (used by tests)
// =============================================================================

// IndexBuilder 辅助类型：用于构建 CARv2 索引（测试用）
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

// Build 构建索引字节数据（使用 go-car/v2 的标准 CarIndexSorted 格式）
func (ib *IndexBuilder) Build() []byte {
	ii := carindex.NewInsertionIndex()
	for _, entry := range ib.entries {
		ii.InsertNoReplace(entry.CID, entry.Offset)
	}
	// Flatten to CarIndexSorted (0x0400) for standard compatibility
	idx, err := ii.Flatten(0x0400)
	if err != nil {
		// Fallback: write InsertionIndex directly (non-standard codec)
		var buf bytes.Buffer
		carindex.WriteTo(ii, &buf)
		return buf.Bytes()
	}
	var buf bytes.Buffer
	if _, err := carindex.WriteTo(idx, &buf); err != nil {
		return nil
	}
	return buf.Bytes()
}

// BuildRaw 构建原始格式索引（使用 go-car/v2）
func (ib *IndexBuilder) BuildRaw() []byte {
	return ib.Build()
}

// EntryCount 返回索引条目数量
func (ib *IndexBuilder) EntryCount() int {
	return len(ib.entries)
}
