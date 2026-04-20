// Package ipfs 提供 IPFS CAR 文件的解析和验证功能
// 支持 CARv1 和 CARv2 格式，专注于桥接场景的验证需求
package ipfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
	"github.com/multiformats/go-varint"
)

// CARv2 魔数 "car\x02"
var carv2Pragma = []byte{0x63, 0x61, 0x72, 0x02}

// CARv1 头部结构
type CarV1Header struct {
	Version uint64
	Roots   []cid.Cid
}

// CARv2 头部结构
type CarV2Header struct {
	Characteristics [16]byte
	DataOffset      uint64
	DataSize        uint64
	IndexOffset     uint64
	IndexSize       uint64
}

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
type CarParser struct {
	reader   io.ReaderAt // 文件读取接口
	fileSize int64       // 文件大小
	info     *CarInfo    // 解析后的元信息
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
)

// NewCarParserFromFile 从文件创建 CAR 解析器
func NewCarParserFromFile(filePath string) (*CarParser, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}

	stat, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to stat file: %v", err)
	}

	return &CarParser{
		reader:   file,
		fileSize: stat.Size(),
		info: &CarInfo{
			FilePath: filePath,
			FileSize: stat.Size(),
		},
	}, nil
}

// NewCarParserFromReader 从 io.ReaderAt 创建 CAR 解析器
func NewCarParserFromReader(reader io.ReaderAt, size int64) (*CarParser, error) {
	if reader == nil {
		return nil, errors.New("reader cannot be nil")
	}
	if size <= 0 {
		return nil, errors.New("invalid file size")
	}

	return &CarParser{
		reader:   reader,
		fileSize: size,
		info: &CarInfo{
			FileSize: size,
		},
	}, nil
}

// Close 关闭解析器（如果底层是文件，会关闭文件）
func (p *CarParser) Close() error {
	if closer, ok := p.reader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// ParseInfo 解析 CAR 文件元信息
// 支持 CARv1 和 CARv2 格式
func (p *CarParser) ParseInfo() (*CarInfo, error) {
	if p.info.Version != 0 {
		return p.info, nil
	}

	version, err := p.readVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to read version: %v", err)
	}

	switch version {
	case 1:
		return p.parseCarV1Info()
	case 2:
		return p.parseCarV2Info()
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedVersion, version)
	}
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

// readVersion 读取 CAR 版本
func (p *CarParser) readVersion() (uint64, error) {
	buf := make([]byte, 16)
	n, err := p.reader.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		return 0, fmt.Errorf("failed to read header: %v", err)
	}
	if n < 4 {
		return 0, ErrInvalidCarFile
	}

	if bytes.Equal(buf[:4], carv2Pragma) {
		return 2, nil
	}

	version, err := varint.ReadUvarint(&byteReader{reader: p.reader, offset: 0})
	if err != nil {
		return 0, ErrCorruptedHeader
	}

	return version, nil
}

// parseCarV1Info 解析 CARv1 元信息
func (p *CarParser) parseCarV1Info() (*CarInfo, error) {
	header, roots, err := p.readCarV1Header()
	if err != nil {
		return nil, err
	}

	p.info.Version = 1
	p.info.Roots = roots
	p.info.DataOffset = header
	p.info.DataSize = uint64(p.fileSize) - header
	p.info.HasIndex = false

	return p.info, nil
}

// parseCarV2Info 解析 CARv2 元信息
func (p *CarParser) parseCarV2Info() (*CarInfo, error) {
	v2Header, err := p.readCarV2Header()
	if err != nil {
		return nil, err
	}

	v1Header, v1Roots, err := p.readCarV1HeaderAt(int64(v2Header.DataOffset))
	if err != nil {
		return nil, fmt.Errorf("failed to read inner CARv1 header: %v", err)
	}

	p.info.Version = 2
	p.info.Roots = v1Roots
	p.info.DataOffset = v2Header.DataOffset + v1Header
	p.info.DataSize = v2Header.DataSize - v1Header
	p.info.IndexOffset = v2Header.IndexOffset
	p.info.IndexSize = v2Header.IndexSize
	p.info.HasIndex = v2Header.IndexOffset > 0 && v2Header.IndexSize > 0

	return p.info, nil
}

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

// readCarV2Header 读取 CARv2 头部
func (p *CarParser) readCarV2Header() (*CarV2Header, error) {
	buf := make([]byte, 48)
	n, err := p.reader.ReadAt(buf, 4)
	if err != nil {
		return nil, fmt.Errorf("failed to read CARv2 header: %v", err)
	}
	if n < 48 {
		return nil, ErrCorruptedHeader
	}

	header := &CarV2Header{}
	copy(header.Characteristics[:], buf[:16])
	header.DataOffset = binary.LittleEndian.Uint64(buf[16:24])
	header.DataSize = binary.LittleEndian.Uint64(buf[24:32])
	header.IndexOffset = binary.LittleEndian.Uint64(buf[32:40])
	header.IndexSize = binary.LittleEndian.Uint64(buf[40:48])

	if header.DataOffset == 0 {
		return nil, fmt.Errorf("%w: invalid data offset", ErrCorruptedHeader)
	}

	return header, nil
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

	if info.IndexOffset+info.IndexSize > uint64(p.fileSize) {
		return fmt.Errorf("%w: index extends beyond file", ErrCorruptedData)
	}

	return nil
}

// GetBlock 通过 CID 获取数据块（需要索引支持）
// 注意：此功能需要外部索引，CAR 文件本身不提供随机访问索引
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
		sectionLen, err := p.readVarintAt(offset)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, nil, fmt.Errorf("failed to read section length at offset %d: %v", offset, err)
		}

		if sectionLen == 0 {
			break
		}

		cidOffset := offset + 1
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

// IterateBlocks 迭代所有数据块
func (p *CarParser) IterateBlocks(handler func(block *Block) error) error {
	info, err := p.ParseInfo()
	if err != nil {
		return err
	}

	offset := int64(info.DataOffset)
	endOffset := int64(info.DataOffset + info.DataSize)

	for offset < endOffset {
		block, _, err := p.readNextBlock(offset, info)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		if err := handler(block); err != nil {
			return err
		}

		offset += 1 + int64(block.CID.ByteLen()) + int64(len(block.Data))
	}

	return nil
}

// readNextBlock 读取下一个数据块
func (p *CarParser) readNextBlock(offset int64, info *CarInfo) (*Block, *BlockMetadata, error) {
	sectionLen, err := p.readVarintAt(offset)
	if err != nil {
		return nil, nil, err
	}

	if sectionLen == 0 {
		return nil, nil, io.EOF
	}

	cidOffset := offset + 1
	buf := make([]byte, sectionLen)
	n, err := p.reader.ReadAt(buf, cidOffset)
	if err != nil && err != io.EOF {
		return nil, nil, fmt.Errorf("failed to read block: %v", err)
	}
	if n < 1 {
		return nil, nil, fmt.Errorf("%w: incomplete block", ErrCorruptedData)
	}

	_, blockCID, err := cid.CidFromBytes(buf[:n])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: invalid CID: %v", ErrCorruptedData, err)
	}

	cidLen := blockCID.ByteLen()
	dataLen := sectionLen - uint64(cidLen)
	dataOffset := cidOffset + int64(cidLen)

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
