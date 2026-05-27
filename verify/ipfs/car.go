// Package ipfs 提供 IPFS CAR 文件的解析和验证功能
// 支持 CARv1 和 CARv2 格式，内部使用 go-car/v2 标准库。
// 同时向后兼容旧的 "car\x02" 非标准格式。
package ipfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	carv2 "github.com/ipld/go-car/v2"
	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
	"github.com/multiformats/go-varint"
)

// 旧格式魔数 "car\x02"（仅用于向后兼容）
var carv2Pragma = []byte{0x63, 0x61, 0x72, 0x02}

// CAR 文件元信息
type CarInfo struct {
	Version     uint64    // CAR 版本 (1 或 2)
	Roots       []cid.Cid // 根 CID 列表
	DataOffset  uint64    // 数据区偏移量
	DataSize    uint64    // 数据区大小
	IndexOffset uint64    // 索引区偏移量 (CARv2)
	IndexSize   uint64    // 索引区大小 (CARv2)
	HasIndex    bool      // 是否包含索引
	FilePath    string    // 文件路径
	FileSize    int64     // 文件总大小
}

// Block 表示 CAR 文件中的一个数据块
type Block struct {
	CID  cid.Cid // 数据块的 CID
	Data []byte  // 数据内容
}

// BlockMetadata 数据块元信息
type BlockMetadata struct {
	CID          cid.Cid // 数据块的 CID
	Offset       uint64  // 在 CARv1 数据区中的偏移量
	SourceOffset uint64  // 在源文件中的偏移量
	Size         uint64  // 数据大小
}

// CarParser CAR 文件解析器
// 内部使用 go-car/v2 标准库，同时兼容旧格式。
type CarParser struct {
	reader   io.ReaderAt // 文件读取接口（go-car/v2 需要）
	fileSize int64       // 文件大小
	info     *CarInfo    // 解析后的元信息

	// 底层 go-car/v2 reader（仅当文件为标准格式时可用）
	carV2Reader *carv2.Reader
	// 旧格式标记
	isLegacy bool
	// 旧格式的 v2 header
	legacyV2Header *legacyCarV2Header
	// 底层文件句柄（用于关闭）
	fileHandle io.Closer
}

// legacyCarV2Header 旧格式 "car\x02" 的 48 字节 header
type legacyCarV2Header struct {
	Characteristics [16]byte
	DataOffset      uint64
	DataSize        uint64
	IndexOffset     uint64
	IndexSize       uint64
}

// 错误定义
var (
	ErrInvalidCarFile     = errors.New("invalid CAR file")
	ErrUnsupportedVersion = errors.New("unsupported CAR version")
	ErrCorruptedHeader    = errors.New("corrupted CAR header")
	ErrCorruptedData      = errors.New("corrupted CAR data")
	ErrBlockNotFound      = errors.New("block not found")
	ErrIndexNotFound      = errors.New("index not found")
	ErrRootMismatch       = errors.New("root CID mismatch")
	ErrInvalidCID         = errors.New("invalid CID")
	ErrInvalidMultihash   = errors.New("invalid multihash")
	// ErrEmptyIndex is declared in index.go
)

// NewCarParserFromFile 从文件创建 CAR 解析器
func NewCarParserFromFile(filePath string) (*CarParser, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	stat, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	// Try to use NewCarParserFromReader which handles all format detection
	p, err := NewCarParserFromReader(file, stat.Size())
	if err != nil {
		file.Close()
		return nil, err
	}
	p.fileHandle = file
	p.info.FilePath = filePath
	return p, nil
}

// NewCarParserFromReader 从 io.ReaderAt 创建 CAR 解析器
func NewCarParserFromReader(reader io.ReaderAt, size int64) (*CarParser, error) {
	if reader == nil {
		return nil, errors.New("reader cannot be nil")
	}
	if size <= 0 {
		return nil, errors.New("invalid file size")
	}

	p := &CarParser{
		reader:   reader,
		fileSize: size,
		info: &CarInfo{
			FileSize: size,
		},
	}

	// 尝试用 go-car/v2 读取（标准 CBOR 格式）
	cr, err := carv2.NewReader(reader)
	if err == nil {
		p.carV2Reader = cr
		return p, nil
	}

	// go-car/v2 失败，检测旧格式
	magic := make([]byte, 4)
	n, rerr := reader.ReadAt(magic, 0)
	// For small files, ReadAt may return partial data with io.EOF — accept it.
	if rerr == nil || (rerr == io.EOF && n >= 1) {
		if n >= 4 && bytes.Equal(magic[:4], carv2Pragma) {
			// 旧 CAR v2 格式 "car\x02"
			p.isLegacy = true
			if err := p.initLegacy(); err != nil {
				return nil, err
			}
			return p, nil
		}

		// 检测旧 CAR v1 格式（varint(version=1)）
		if n >= 1 && magic[0] == 0x01 {
			p.isLegacy = true
			p.legacyV2Header = nil // signals v1
			return p, nil
		}
	}

	return nil, fmt.Errorf("failed to create CAR reader: %w", err)
}

// isLegacyFormat 检测是否为旧 "car\x02" 格式
func isLegacyFormat(f *os.File) bool {
	magic := make([]byte, 4)
	if _, err := f.ReadAt(magic, 0); err != nil {
		return false
	}
	if bytes.Equal(magic, carv2Pragma) {
		return true
	}
	// 也支持 CBOR pragma（标准格式），此时返回 false
	return false
}

// initLegacy 初始化旧格式解析
func (p *CarParser) initLegacy() error {
	buf := make([]byte, 4+48) // 4 bytes magic + 48 bytes header
	n, err := p.reader.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		return fmt.Errorf("failed to read legacy header: %w", err)
	}
	if n < 4+48 {
		return ErrCorruptedHeader
	}

	hdr := &legacyCarV2Header{}
	copy(hdr.Characteristics[:], buf[4:20])
	hdr.DataOffset = binary.LittleEndian.Uint64(buf[20:28])
	hdr.DataSize = binary.LittleEndian.Uint64(buf[28:36])
	hdr.IndexOffset = binary.LittleEndian.Uint64(buf[36:44])
	hdr.IndexSize = binary.LittleEndian.Uint64(buf[44:52])

	if hdr.DataOffset == 0 {
		return fmt.Errorf("%w: invalid data offset", ErrCorruptedHeader)
	}

	p.legacyV2Header = hdr
	return nil
}

// Close 关闭解析器（如果底层是文件，会关闭文件）
func (p *CarParser) Close() error {
	if p.carV2Reader != nil {
		p.carV2Reader.Close()
	}
	if p.fileHandle != nil {
		return p.fileHandle.Close()
	}
	if closer, ok := p.reader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// ParseInfo 解析 CAR 文件元信息
func (p *CarParser) ParseInfo() (*CarInfo, error) {
	if p.info.Version != 0 {
		return p.info, nil
	}

	if p.isLegacy {
		if p.legacyV2Header != nil {
			return p.parseLegacyInfo()
		}
		// Legacy CAR v1
		return p.parseLegacyV1Info()
	}

	if p.carV2Reader != nil {
		return p.parseStandardInfo()
	}

	return nil, ErrInvalidCarFile
}

// parseStandardInfo 使用 go-car/v2 解析标准格式
func (p *CarParser) parseStandardInfo() (*CarInfo, error) {
	cr := p.carV2Reader

	p.info.Version = cr.Version

	roots, err := cr.Roots()
	if err != nil {
		return nil, fmt.Errorf("failed to read roots: %w", err)
	}
	p.info.Roots = roots

	p.info.IndexOffset = cr.Header.IndexOffset
	p.info.HasIndex = cr.Header.HasIndex()

	if p.info.HasIndex {
		p.info.IndexSize = uint64(p.fileSize) - p.info.IndexOffset
	}

	// cr.Header.DataOffset points to the start of CAR v1 data (including the CBOR v1 header).
	// We need to skip the CBOR v1 header to get to the block data.
	v1HeaderSize, err := p.readCBORV1HeaderSize(cr.Header.DataOffset)
	if err != nil {
		return nil, fmt.Errorf("failed to read CAR v1 header size: %w", err)
	}

	p.info.DataOffset = cr.Header.DataOffset + v1HeaderSize
	p.info.DataSize = cr.Header.DataSize - v1HeaderSize

	return p.info, nil
}

// readCBORV1HeaderSize reads the size of a CBOR-encoded CAR v1 header.
// The header format is: ld-varint(cbor_len) + CBOR_data.
func (p *CarParser) readCBORV1HeaderSize(offset uint64) (uint64, error) {
	cborLen, varintSize, err := p.readVarintSizeAt(int64(offset))
	if err != nil {
		return 0, fmt.Errorf("failed to read CBOR v1 header length: %w", err)
	}
	return uint64(varintSize) + cborLen, nil
}

// parseLegacyInfo 解析旧格式元信息
func (p *CarParser) parseLegacyInfo() (*CarInfo, error) {
	hdr := p.legacyV2Header

	p.info.Version = 2
	p.info.DataOffset = hdr.DataOffset
	p.info.DataSize = hdr.DataSize
	p.info.IndexOffset = hdr.IndexOffset
	p.info.IndexSize = hdr.IndexSize
	p.info.HasIndex = hdr.IndexOffset > 0 && hdr.IndexSize > 0

	// 解析内嵌的 CARv1 header 获取 root CIDs
	v1HeaderSize, roots, err := p.readCarV1HeaderAt(int64(hdr.DataOffset))
	if err != nil {
		return nil, fmt.Errorf("failed to read inner CARv1 header: %w", err)
	}
	p.info.Roots = roots

	// 调整 DataOffset 和 DataSize 指向 CARv1 数据区
	p.info.DataOffset = hdr.DataOffset + v1HeaderSize
	p.info.DataSize = hdr.DataSize - v1HeaderSize

	return p.info, nil
}

// parseLegacyV1Info 解析旧格式 CAR v1 元信息（varint-based header）
func (p *CarParser) parseLegacyV1Info() (*CarInfo, error) {
	v1HeaderSize, roots, err := p.readCarV1HeaderAt(0)
	if err != nil {
		return nil, fmt.Errorf("failed to read legacy CAR v1 header: %w", err)
	}

	p.info.Version = 1
	p.info.Roots = roots
	p.info.DataOffset = v1HeaderSize
	p.info.DataSize = uint64(p.fileSize) - v1HeaderSize
	p.info.HasIndex = false

	return p.info, nil
}

// =============================================================================
// Standalone utility functions
// =============================================================================

// ParseIndexData parses CAR v2 index data bytes into a CID→offset map.
// Supports both standard go-car/v2 index format and legacy formats.
func ParseIndexData(indexData []byte) (map[string]uint64, error) {
	if len(indexData) == 0 {
		return nil, ErrEmptyIndex
	}

	// 首先尝试使用 go-car/v2 的 index.ReadFrom
	result := make(map[string]uint64)

	// 尝试标准格式
	idx, err := carv2indexReadFrom(bytes.NewReader(indexData))
	if err == nil {
		// 尝试通过 ForEach 迭代（如果支持）
		if err := carv2indexPopulateMap(idx, result); err == nil {
			return result, nil
		}
	}

	// 回退：使用自实现的解析器
	return parseIndexDataFallback(indexData)
}

// ExtractBlockFromCar extracts a single IPFS block from CAR data at the given offset.
// carData is a byte slice containing CAR-format data (typically an HTTP Range response).
// offset is the position within carData where the target block starts (0 for Range-aligned reads).
// Returns the pure data payload of the block (without the CID/varint framing).
func ExtractBlockFromCar(carData []byte, offset uint64) ([]byte, error) {
	if len(carData) == 0 {
		return nil, fmt.Errorf("ExtractBlockFromCar: empty car data")
	}
	if offset >= uint64(len(carData)) {
		return nil, fmt.Errorf("ExtractBlockFromCar: offset %d exceeds data length %d", offset, len(carData))
	}

	data := carData[offset:]

	// Read section length (varint)
	sectionLen, n, err := readVarintFromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("ExtractBlockFromCar: failed to read section length: %w", err)
	}
	if sectionLen == 0 {
		return nil, fmt.Errorf("ExtractBlockFromCar: zero-length section")
	}

	pos := n

	// Read CID from the section
	if pos >= len(data) {
		return nil, fmt.Errorf("ExtractBlockFromCar: data too short for CID")
	}

	cidBytes := make([]byte, sectionLen)
	copyLen := int(sectionLen)
	if copyLen > len(data[pos:]) {
		copyLen = len(data[pos:])
	}
	copy(cidBytes, data[pos:])

	_, blockCID, err := cid.CidFromBytes(cidBytes)
	if err != nil {
		return nil, fmt.Errorf("ExtractBlockFromCar: invalid CID: %w", err)
	}

	cidLen := blockCID.ByteLen()
	dataLen := int(sectionLen) - cidLen
	dataStart := pos + cidLen

	if dataLen < 0 {
		return nil, fmt.Errorf("ExtractBlockFromCar: invalid block: CID length %d > section length %d", cidLen, sectionLen)
	}

	if dataStart+dataLen > len(data) {
		return nil, fmt.Errorf("ExtractBlockFromCar: data extends beyond available bytes (need %d, have %d)", dataStart+dataLen, len(data))
	}

	blockData := make([]byte, dataLen)
	copy(blockData, data[dataStart:dataStart+dataLen])

	return blockData, nil
}

// readVarintFromBytes reads a varint from a byte slice, returning the value and bytes consumed.
func readVarintFromBytes(data []byte) (uint64, int, error) {
	value, n, err := varint.FromUvarint(data)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid varint: %w", err)
	}
	if n <= 0 {
		return 0, 0, fmt.Errorf("invalid varint: zero-length read")
	}
	return value, n, nil
}

// =============================================================================
// readerAtWrapper 包装 io.ReaderAt 为 io.ReadSeeker（用于 go-car/v2）
// =============================================================================

type readerAtWrapper struct {
	r      io.ReaderAt
	offset int64
}

func (w *readerAtWrapper) Read(p []byte) (int, error) {
	n, err := w.r.ReadAt(p, w.offset)
	if err != nil && err != io.EOF {
		return n, err
	}
	w.offset += int64(n)
	return n, err
}

func (w *readerAtWrapper) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		w.offset = offset
	case io.SeekCurrent:
		w.offset += offset
	case io.SeekEnd:
		w.offset = 0 // not supported
	default:
		return 0, fmt.Errorf("invalid whence")
	}
	return w.offset, nil
}

// byteReader 实现 io.ByteReader 接口
type byteReader struct {
	reader io.ReaderAt
	offset int64
}

func (br *byteReader) ReadByte() (byte, error) {
	var b [1]byte
	_, err := br.reader.ReadAt(b[:], br.offset)
	if err == nil {
		br.offset++
	}
	return b[0], err
}

func (br *byteReader) Read(p []byte) (n int, err error) {
	n, err = br.reader.ReadAt(p, br.offset)
	if err == nil {
		br.offset += int64(n)
	}
	return n, err
}

// =============================================================================
// CARv1 header reading (used for legacy format)
// =============================================================================

// readCarV1Header 读取 CARv1 头部
func (p *CarParser) readCarV1Header() (uint64, []cid.Cid, error) {
	return p.readCarV1HeaderAt(0)
}

// readCarV1HeaderAt 从指定位置读取 CARv1 头部
func (p *CarParser) readCarV1HeaderAt(offset int64) (uint64, []cid.Cid, error) {
	br := &byteReader{reader: p.reader, offset: offset}

	version, err := varint.ReadUvarint(br)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to read version: %v", err)
	}

	if version != 1 {
		return 0, nil, fmt.Errorf("%w: expected 1, got %d", ErrUnsupportedVersion, version)
	}

	rootCount, err := varint.ReadUvarint(br)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to read root count: %v", err)
	}

	headerSize := uint64(br.offset - offset)
	roots := make([]cid.Cid, rootCount)

	for i := uint64(0); i < rootCount; i++ {
		cidLen, err := varint.ReadUvarint(br)
		if err != nil {
			return 0, nil, fmt.Errorf("failed to read root CID length: %v", err)
		}

		cidBuf := make([]byte, cidLen)
		n, err := br.Read(cidBuf)
		if err != nil {
			return 0, nil, fmt.Errorf("failed to read root CID: %v", err)
		}
		if uint64(n) != cidLen {
			return 0, nil, ErrCorruptedHeader
		}

		rootCID, err := cid.Cast(cidBuf)
		if err != nil {
			return 0, nil, fmt.Errorf("invalid root CID: %v", err)
		}

		roots[i] = rootCID
		headerSize += 1 + cidLen
	}

	return headerSize, roots, nil
}

// =============================================================================
// Public methods (delegating to go-car/v2 where possible)
// =============================================================================

// ValidateRoots 验证根 CIDs
func (p *CarParser) ValidateRoots(expectedRoots []cid.Cid) error {
	info, err := p.ParseInfo()
	if err != nil {
		return err
	}

	if len(info.Roots) != len(expectedRoots) {
		return fmt.Errorf("%w: expected %d roots, got %d", ErrRootMismatch, len(expectedRoots), len(info.Roots))
	}

	for i, root := range info.Roots {
		if !root.Equals(expectedRoots[i]) {
			return fmt.Errorf("%w: root %d mismatch", ErrRootMismatch, i)
		}
	}

	return nil
}

// ValidateIndex 验证索引是否存在（针对 CARv2）
func (p *CarParser) ValidateIndex() error {
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

	if p.isLegacy {
		if info.IndexOffset+info.IndexSize > uint64(p.fileSize) {
			return fmt.Errorf("%w: index extends beyond file", ErrCorruptedData)
		}
		return nil
	}

	// Standard (go-car/v2) format: attempt to parse the index to verify
	// it is complete and not truncated. A truncated file will cause
	// carindex.ReadFrom to return "unexpected EOF".
	if _, err := p.ParseIndex(); err != nil {
		return fmt.Errorf("index parse failed: %w", err)
	}

	return nil
}

// GetBlock 通过 CID 获取数据块（需要索引支持）
func (p *CarParser) GetBlock(targetCID cid.Cid) (*Block, error) {
	block, _, err := p.findBlockByCID(targetCID)
	return block, err
}

// GetBlockMetadata 通过 CID 获取数据块元信息
func (p *CarParser) GetBlockMetadata(targetCID cid.Cid) (*BlockMetadata, error) {
	_, metadata, err := p.findBlockByCID(targetCID)
	return metadata, err
}

// findBlockByCID 通过 CID 查找数据块（顺序扫描）
func (p *CarParser) findBlockByCID(targetCID cid.Cid) (*Block, *BlockMetadata, error) {
	info, err := p.ParseInfo()
	if err != nil {
		return nil, nil, err
	}

	offset := int64(info.DataOffset)
	endOffset := int64(info.DataOffset + info.DataSize)

	for offset < endOffset {
		sectionLen, varintSize, err := p.readVarintSizeAt(offset)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, nil, fmt.Errorf("failed to read section length at offset %d: %v", offset, err)
		}

		if sectionLen == 0 {
			break
		}

		cidOffset := offset + int64(varintSize)
		cidBuf := make([]byte, sectionLen)
		n, err := p.reader.ReadAt(cidBuf, cidOffset)
		if err != nil && err != io.EOF {
			return nil, nil, fmt.Errorf("failed to read block at offset %d: %v", offset, err)
		}
		if n < 1 {
			return nil, nil, fmt.Errorf("%w: incomplete block at offset %d", ErrCorruptedData, offset)
		}

		_, blockCID, err := cid.CidFromBytes(cidBuf[:n])
		if err != nil {
			return nil, nil, fmt.Errorf("%w: invalid CID at offset %d: %v", ErrCorruptedData, offset, err)
		}

		cidLen := blockCID.ByteLen()
		dataLen := sectionLen - uint64(cidLen)
		dataOffset := cidOffset + int64(cidLen)

		if blockCID.Equals(targetCID) {
			dataBuf := make([]byte, dataLen)
			n, err = p.reader.ReadAt(dataBuf, dataOffset)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read block data: %v", err)
			}
			if uint64(n) != dataLen {
				return nil, nil, fmt.Errorf("%w: incomplete block data", ErrCorruptedData)
			}

			block := &Block{
				CID:  blockCID,
				Data: dataBuf,
			}

			metadata := &BlockMetadata{
				CID:          blockCID,
				Offset:       uint64(cidOffset - int64(info.DataOffset)),
				SourceOffset: uint64(cidOffset),
				Size:         dataLen,
			}

			return block, metadata, nil
		}

		offset = dataOffset + int64(dataLen)
	}

	return nil, nil, fmt.Errorf("%w: %s", ErrBlockNotFound, targetCID.String())
}

// readVarintSizeAt reads a varint from the given offset and returns both
// the decoded value and the number of bytes consumed.
func (p *CarParser) readVarintSizeAt(offset int64) (uint64, int, error) {
	br := &byteReader{reader: p.reader, offset: offset}
	value, err := varint.ReadUvarint(br)
	if err != nil {
		return 0, 0, err
	}
	bytesRead := int(br.offset - offset)
	return value, bytesRead, nil
}

// readVarintAt 从指定位置读取 varint
func (p *CarParser) readVarintAt(offset int64) (uint64, error) {
	br := &byteReader{reader: p.reader, offset: offset}
	value, err := varint.ReadUvarint(br)
	if err != nil {
		return 0, err
	}
	return value, nil
}

// IterateBlocks 迭代所有数据块
func (p *CarParser) IterateBlocks(handler func(block *Block) error) error {
	info, err := p.ParseInfo()
	if err != nil {
		return err
	}

	offset := int64(info.DataOffset)
	endOffset := int64(info.DataOffset + info.DataSize)

	for offset < endOffset {
		sectionLen, varintSize, err := p.readVarintSizeAt(offset)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		if sectionLen == 0 {
			break
		}

		cidOffset := offset + int64(varintSize)
		buf := make([]byte, sectionLen)
		n, err := p.reader.ReadAt(buf, cidOffset)
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read block: %v", err)
		}
		if n < 1 {
			return fmt.Errorf("%w: incomplete block", ErrCorruptedData)
		}

		_, blockCID, err := cid.CidFromBytes(buf[:n])
		if err != nil {
			return fmt.Errorf("%w: invalid CID: %v", ErrCorruptedData, err)
		}

		cidLen := blockCID.ByteLen()
		dataLen := sectionLen - uint64(cidLen)
		dataOffset := cidOffset + int64(cidLen)

		dataBuf := make([]byte, dataLen)
		n, err = p.reader.ReadAt(dataBuf, dataOffset)
		if err != nil {
			return fmt.Errorf("failed to read block data: %v", err)
		}
		if uint64(n) != dataLen {
			return fmt.Errorf("%w: incomplete block data", ErrCorruptedData)
		}

		block := &Block{
			CID:  blockCID,
			Data: dataBuf,
		}

		if err := handler(block); err != nil {
			return err
		}

		offset = dataOffset + int64(dataLen)
	}

	return nil
}

// ValidateBlockIntegrity 验证数据块完整性
func (p *CarParser) ValidateBlockIntegrity(block *Block) error {
	if block == nil {
		return errors.New("block cannot be nil")
	}

	if !block.CID.Defined() {
		return ErrInvalidCID
	}

	hash, err := block.CID.Prefix().Sum(block.Data)
	if err != nil {
		return fmt.Errorf("failed to compute hash: %v", err)
	}

	if !hash.Equals(block.CID) {
		return fmt.Errorf("%w: expected %s, got %s", ErrCorruptedData, block.CID.String(), hash.String())
	}

	return nil
}

// ValidateMultihash 验证 multihash 格式
func ValidateMultihash(mh multihash.Multihash) error {
	if mh == nil || len(mh) == 0 {
		return ErrInvalidMultihash
	}

	_, err := multihash.Decode(mh)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidMultihash, err)
	}

	return nil
}

// GetRootCID 获取第一个根 CID
func (p *CarParser) GetRootCID() (cid.Cid, error) {
	info, err := p.ParseInfo()
	if err != nil {
		return cid.Undef, err
	}

	if len(info.Roots) == 0 {
		return cid.Undef, errors.New("no root CIDs found")
	}

	return info.Roots[0], nil
}

// GetRootCIDs 获取所有根 CID
func (p *CarParser) GetRootCIDs() ([]cid.Cid, error) {
	info, err := p.ParseInfo()
	if err != nil {
		return nil, err
	}

	return info.Roots, nil
}

// IsCarV2 检查是否为 CARv2 格式
func (p *CarParser) IsCarV2() (bool, error) {
	info, err := p.ParseInfo()
	if err != nil {
		return false, err
	}

	return info.Version == 2, nil
}

// HasIndex 检查是否包含索引
func (p *CarParser) HasIndex() (bool, error) {
	info, err := p.ParseInfo()
	if err != nil {
		return false, err
	}

	return info.HasIndex, nil
}

// GetFileSize 获取文件大小
func (p *CarParser) GetFileSize() int64 {
	return p.fileSize
}

// GetInfo 获取已解析的元信息
func (p *CarParser) GetInfo() (*CarInfo, error) {
	if p.info.Version == 0 {
		return p.ParseInfo()
	}
	return p.info, nil
}

// =============================================================================
// Index-related helpers (for index.go and bridge/fetcher.go compatibility)
// =============================================================================

// readIndexData 读取索引段原始数据
func (p *CarParser) readIndexData() ([]byte, error) {
	info, err := p.ParseInfo()
	if err != nil {
		return nil, err
	}

	if info.Version != 2 || !info.HasIndex {
		return nil, ErrIndexNotFound
	}

	indexData := make([]byte, info.IndexSize)
	n, err := p.reader.ReadAt(indexData, int64(info.IndexOffset))
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to read index data: %v", err)
	}
	if uint64(n) < info.IndexSize {
		return nil, fmt.Errorf("short read: expected %d bytes, got %d", info.IndexSize, n)
	}
	return indexData, nil
}

// readVarint 从字节切片读取 varint
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
