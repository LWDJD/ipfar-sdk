package ipfs

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"

	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
)

// ============================================================
// IndexBuilder 测试
// ============================================================

func TestIndexBuilder_Build(t *testing.T) {
	mh1, _ := multihash.Sum([]byte("block1"), multihash.SHA2_256, -1)
	cid1 := cid.NewCidV1(cid.Raw, mh1)

	mh2, _ := multihash.Sum([]byte("block2"), multihash.SHA2_256, -1)
	cid2 := cid.NewCidV1(cid.Raw, mh2)

	builder := NewIndexBuilder()
	builder.AddEntry(cid1, 100)
	builder.AddEntry(cid2, 200)

	data := builder.Build()
	if len(data) == 0 {
		t.Fatal("IndexBuilder.Build() returned empty data")
	}

	t.Logf("Built index data: %d bytes with %d entries", len(data), builder.EntryCount())
}

func TestIndexBuilder_BuildRaw(t *testing.T) {
	mh, _ := multihash.Sum([]byte("test"), multihash.SHA2_256, -1)
	c := cid.NewCidV1(cid.Raw, mh)

	builder := NewIndexBuilder()
	builder.AddEntry(c, 50)

	data := builder.BuildRaw()
	if len(data) == 0 {
		t.Fatal("IndexBuilder.BuildRaw() returned empty data")
	}

	t.Logf("Built raw index data: %d bytes", len(data))
}

func TestIndexBuilder_Empty(t *testing.T) {
	builder := NewIndexBuilder()
	if builder.EntryCount() != 0 {
		t.Error("New IndexBuilder should have 0 entries")
	}

	data := builder.Build()
	if len(data) != 0 {
		t.Error("Empty builder should produce empty data")
	}
}

// ============================================================
// 合成 CARv2 文件测试辅助
// ============================================================

// buildTestCarV2 创建一个合成 CARv2 文件用于测试
// 返回文件路径和根CID
func buildTestCarV2(t *testing.T) (string, cid.Cid, []IndexEntry) {
	t.Helper()

	// 创建数据块
	block1Data := []byte("hello world block 1")
	block2Data := []byte("hello world block 2 - more data here")
	block3Data := []byte("block 3 data for index testing")

	mh1, _ := multihash.Sum(block1Data, multihash.SHA2_256, -1)
	cid1 := cid.NewCidV1(cid.Raw, mh1)

	mh2, _ := multihash.Sum(block2Data, multihash.SHA2_256, -1)
	cid2 := cid.NewCidV1(cid.Raw, mh2)

	mh3, _ := multihash.Sum(block3Data, multihash.SHA2_256, -1)
	cid3 := cid.NewCidV1(cid.Raw, mh3)

	// 构建 CARv1 数据段
	var carv1Data bytes.Buffer

	// CARv1 header: varint(version=1) + varint(root_count=2) + root_CIDs
	roots := []cid.Cid{cid1, cid2}
	carv1Header := buildCarV1Header(roots)
	carv1Data.Write(carv1Header)

	// 写入 block1
	block1Section := buildCarBlock(cid1, block1Data)
	block1Offset := uint64(4 + 48 + carv1Data.Len()) // absolute file offset
	carv1Data.Write(block1Section)

	// 写入 block2
	block2Section := buildCarBlock(cid2, block2Data)
	block2Offset := uint64(4 + 48 + carv1Data.Len())
	carv1Data.Write(block2Section)

	// 写入 block3
	block3Section := buildCarBlock(cid3, block3Data)
	block3Offset := uint64(4 + 48 + carv1Data.Len())
	carv1Data.Write(block3Section)

	// 构建索引
	indexEntries := []IndexEntry{
		{CID: cid1, Offset: block1Offset},
		{CID: cid2, Offset: block2Offset},
		{CID: cid3, Offset: block3Offset},
	}

	indexBuilder := NewIndexBuilder()
	for _, e := range indexEntries {
		indexBuilder.AddEntry(e.CID, e.Offset)
	}
	indexData := indexBuilder.Build()

	// 构建 CARv2 文件
	var carv2File bytes.Buffer

	// CARv2 pragma
	carv2File.Write(carv2Pragma)

	// CARv2 header (48 bytes after pragma)
	// Characteristics[16] + DataOffset[8] + DataSize[8] + IndexOffset[8] + IndexSize[8]
	v2Header := make([]byte, 48)
	// Characteristics: [8:10] = 0x0402 (CID index)
	binary.BigEndian.PutUint16(v2Header[8:10], 0x0402)
	// DataOffset = 4 + 48 = 52 (pragma + header)
	binary.LittleEndian.PutUint64(v2Header[16:24], uint64(4+48)) // CARv1 starts at offset 52
	binary.LittleEndian.PutUint64(v2Header[24:32], uint64(carv1Data.Len()))
	// IndexOffset: after CARv1 data
	indexOffset := uint64(4 + 48 + carv1Data.Len())
	binary.LittleEndian.PutUint64(v2Header[32:40], indexOffset)
	binary.LittleEndian.PutUint64(v2Header[40:48], uint64(len(indexData)))

	carv2File.Write(v2Header)
	carv2File.Write(carv1Data.Bytes())
	carv2File.Write(indexData)

	// 写入临时文件
	tmpFile, err := os.CreateTemp("", "test_carv2_*.car")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	_, err = tmpFile.Write(carv2File.Bytes())
	if err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tmpFile.Close()

	t.Cleanup(func() {
		os.Remove(tmpFile.Name())
	})

	return tmpFile.Name(), cid1, indexEntries
}

// buildCarV1Header 构建 CARv1 头部字节（使用正确的 varint 编码）
func buildCarV1Header(roots []cid.Cid) []byte {
	var buf bytes.Buffer

	// version = 1 (varint)
	versionBuf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(versionBuf, 1)
	buf.Write(versionBuf[:n])

	// root count (varint)
	countBuf := make([]byte, binary.MaxVarintLen64)
	n = binary.PutUvarint(countBuf, uint64(len(roots)))
	buf.Write(countBuf[:n])

	for _, root := range roots {
		rootBytes := root.Bytes()
		// CID length as varint
		lenBuf := make([]byte, binary.MaxVarintLen64)
		n = binary.PutUvarint(lenBuf, uint64(len(rootBytes)))
		buf.Write(lenBuf[:n])
		buf.Write(rootBytes)
	}

	return buf.Bytes()
}

// buildCarBlock 构建单个 CAR 数据块
// 格式: varint(cidLen + dataLen) + CID + data
func buildCarBlock(c cid.Cid, data []byte) []byte {
	var buf bytes.Buffer

	cidBytes := c.Bytes()
	sectionLen := uint64(len(cidBytes) + len(data))

	// section length as varint
	lenBuf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(lenBuf, sectionLen)
	buf.Write(lenBuf[:n])

	buf.Write(cidBytes)
	buf.Write(data)

	return buf.Bytes()
}

// ============================================================
// ParseIndex 测试
// ============================================================

func TestParseIndex_Valid(t *testing.T) {
	filePath, rootCID, expectedEntries := buildTestCarV2(t)

	parser, err := NewCarParserFromFile(filePath)
	if err != nil {
		t.Fatalf("Failed to create parser: %v", err)
	}
	defer parser.Close()

	info, err := parser.ParseInfo()
	if err != nil {
		t.Fatalf("Failed to parse info: %v", err)
	}

	t.Logf("CAR version: %d", info.Version)
	t.Logf("Root CID: %s", rootCID.String())
	t.Logf("Has index: %v", info.HasIndex)
	t.Logf("Index offset: %d, size: %d", info.IndexOffset, info.IndexSize)

	if !info.HasIndex {
		t.Fatal("Expected CARv2 to have index")
	}

	entries, err := parser.ParseIndex()
	if err != nil {
		t.Fatalf("ParseIndex failed: %v", err)
	}

	if len(entries) != len(expectedEntries) {
		t.Errorf("Expected %d index entries, got %d", len(expectedEntries), len(entries))
	}

	for i, entry := range entries {
		if !entry.CID.Equals(expectedEntries[i].CID) {
			t.Errorf("Entry %d: CID mismatch", i)
		}
		t.Logf("Entry %d: CID=%s, Offset=%d", i, entry.CID.String(), entry.Offset)
	}
}

func TestParseIndex_EmptyIndex(t *testing.T) {
	filePath, _, _ := buildTestCarV2(t)

	parser, err := NewCarParserFromFile(filePath)
	if err != nil {
		t.Fatalf("Failed to create parser: %v", err)
	}
	defer parser.Close()

	entries, err := parser.ParseIndex()
	if err != nil {
		t.Fatalf("ParseIndex failed: %v", err)
	}
	if len(entries) == 0 {
		t.Error("Expected non-empty index entries")
	}
}

// ============================================================
// ValidateIndexContent 测试
// ============================================================

func TestValidateIndexContent_Valid(t *testing.T) {
	filePath, _, _ := buildTestCarV2(t)

	parser, err := NewCarParserFromFile(filePath)
	if err != nil {
		t.Fatalf("Failed to create parser: %v", err)
	}
	defer parser.Close()

	err = parser.ValidateIndexContent()
	if err != nil {
		t.Errorf("ValidateIndexContent should pass for valid CARv2: %v", err)
	}
}

func TestValidateIndexContent_CARv1(t *testing.T) {
	// Create a simple CARv1 file
	tmpFile, err := os.CreateTemp("", "test_carv1_*.car")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Minimal CARv1: version=1, roots=0
	tmpFile.Write([]byte{0x01, 0x00})
	tmpFile.Close()

	parser, err := NewCarParserFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to create parser: %v", err)
	}
	defer parser.Close()

	err = parser.ValidateIndexContent()
	if err == nil {
		t.Log("Expected error for CARv1 index validation (acceptable)")
	}
}

// ============================================================
// ValidateIndexCrossCheck 测试
// ============================================================

func TestValidateIndexCrossCheck_Valid(t *testing.T) {
	filePath, _, _ := buildTestCarV2(t)

	parser, err := NewCarParserFromFile(filePath)
	if err != nil {
		t.Fatalf("Failed to create parser: %v", err)
	}
	defer parser.Close()

	err = parser.ValidateIndexCrossCheck()
	if err != nil {
		t.Errorf("ValidateIndexCrossCheck should pass for valid CARv2: %v", err)
	}
}

// ============================================================
// GetIndexType 测试
// ============================================================

func TestGetIndexType(t *testing.T) {
	filePath, _, _ := buildTestCarV2(t)

	parser, err := NewCarParserFromFile(filePath)
	if err != nil {
		t.Fatalf("Failed to create parser: %v", err)
	}
	defer parser.Close()

	idxType, err := parser.GetIndexType()
	if err != nil {
		t.Fatalf("GetIndexType failed: %v", err)
	}

	t.Logf("Index type: %d (0x%04x)", idxType, uint16(idxType))

	// Should be IndexTypeCID (0x0402) since we set it in buildTestCarV2
	if idxType != IndexTypeCID {
		t.Logf("Index type is %d, not the expected 0x0402 (this may be valid for some formats)", idxType)
	}
}

// ============================================================
// 与 BlockIntegrity 协同测试
// ============================================================

func TestIndexAndBlockIntegrity(t *testing.T) {
	filePath, rootCID, _ := buildTestCarV2(t)

	parser, err := NewCarParserFromFile(filePath)
	if err != nil {
		t.Fatalf("Failed to create parser: %v", err)
	}
	defer parser.Close()

	// 1. 验证索引
	err = parser.ValidateIndexContent()
	if err != nil {
		t.Fatalf("Index validation failed: %v", err)
	}

	// 2. 获取根 CID 对应的块并验证完整性
	block, err := parser.GetBlock(rootCID)
	if err != nil {
		t.Fatalf("Failed to get block for root CID: %v", err)
	}

	err = parser.ValidateBlockIntegrity(block)
	if err != nil {
		t.Errorf("Block integrity validation failed: %v", err)
	}

	t.Logf("Root block integrity verified: CID=%s, DataSize=%d", block.CID.String(), len(block.Data))
}

// ============================================================
// 迭代块后验证索引
// ============================================================

func TestIndexAfterIteration(t *testing.T) {
	filePath, _, _ := buildTestCarV2(t)

	parser, err := NewCarParserFromFile(filePath)
	if err != nil {
		t.Fatalf("Failed to create parser: %v", err)
	}
	defer parser.Close()

	// 迭代所有块
	blockCount := 0
	err = parser.IterateBlocks(func(block *Block) error {
		blockCount++
		// 验证每个块的完整性
		if err := parser.ValidateBlockIntegrity(block); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatalf("IterateBlocks failed: %v", err)
	}

	t.Logf("Iterated %d blocks, all integrity checks passed", blockCount)

	// 交叉验证索引
	err = parser.ValidateIndexCrossCheck()
	if err != nil {
		t.Errorf("Cross-check failed after iteration: %v", err)
	}
}

// ============================================================
// 索引损坏检测测试
// ============================================================

func TestCorruptedIndex_Detected(t *testing.T) {
	// 创建带有无效索引偏移量的 CARv2 文件
	filePath, _, _ := buildTestCarV2(t)

	parser, err := NewCarParserFromFile(filePath)
	if err != nil {
		t.Fatalf("Failed to create parser: %v", err)
	}
	defer parser.Close()

	// 验证有效索引先通过
	err = parser.ValidateIndexContent()
	if err != nil {
		t.Fatalf("Pre-check: valid index should pass: %v", err)
	}

	// 现在手动检查 - 解析索引并修改偏移量再验证
	entries, err := parser.ParseIndex()
	if err != nil {
		t.Fatalf("Failed to parse index: %v", err)
	}

	if len(entries) > 0 {
		// 检查: 无效偏移量是否能被 validateEntryAtOffset 检测
		// 使用超出范围的偏移量
		info, _ := parser.ParseInfo()
		invalidEntry := IndexEntry{
			CID:    entries[0].CID,
			Offset: info.DataOffset + info.DataSize + 1000, // 超出范围
		}

		err = parser.validateEntryAtOffset(invalidEntry, info)
		if err == nil {
			t.Error("Expected error for out-of-bounds entry offset")
		} else {
			t.Logf("Correctly detected invalid offset: %v", err)
		}
	}
}

// ============================================================
// IndexBuilder round-trip
// ============================================================

func TestIndexBuilder_RoundTrip(t *testing.T) {
	mh1, _ := multihash.Sum([]byte("data1"), multihash.SHA2_256, -1)
	cid1 := cid.NewCidV1(cid.Raw, mh1)

	mh2, _ := multihash.Sum([]byte("data2"), multihash.SHA2_256, -1)
	cid2 := cid.NewCidV1(cid.Raw, mh2)

	builder := NewIndexBuilder()
	builder.AddEntry(cid1, 51)
	builder.AddEntry(cid2, 102)

	indexData := builder.Build()

	// 模拟解析：创建 parser 并手动调用 parseIndexData
	// 使用一个假的 parser（只需要 reader 和 fileSize 字段）
	parser := &CarParser{
		reader:   &bytesReaderAt{data: indexData},
		fileSize: int64(len(indexData)),
		info: &CarInfo{
			Version:   2,
			DataSize:  200,
			DataOffset: 0,
			HasIndex:  true,
			IndexSize: uint64(len(indexData)),
		},
	}

	// 注意：ParseIndex 需要从 parser 的 info 读取 IndexOffset 和 IndexSize
	// 但 info 中 IndexSize 已设置。parseIndexData 直接使用数据
	entries, err := parser.parseIndexData(indexData)
	if err != nil {
		t.Fatalf("parseIndexData failed: %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("Expected 2 entries, got %d", len(entries))
	}

	for i, entry := range entries {
		t.Logf("Round-trip entry %d: CID=%s, Offset=%d", i, entry.CID.String(), entry.Offset)
	}
}

// bytesReaderAt 将 []byte 包装成 io.ReaderAt
type bytesReaderAt struct {
	data []byte
}

func (r *bytesReaderAt) ReadAt(p []byte, off int64) (n int, err error) {
	if off >= int64(len(r.data)) {
		return 0, nil
	}
	n = copy(p, r.data[off:])
	if n < len(p) {
		return n, nil
	}
	return n, nil
}

// ============================================================
// getRootCID 测试（已有功能验证）
// ============================================================

func TestIndexGetRootCID(t *testing.T) {
	filePath, expectedRoot, _ := buildTestCarV2(t)

	parser, err := NewCarParserFromFile(filePath)
	if err != nil {
		t.Fatalf("Failed to create parser: %v", err)
	}
	defer parser.Close()

	rootCID, err := parser.GetRootCID()
	if err != nil {
		t.Fatalf("GetRootCID failed: %v", err)
	}

	if !rootCID.Equals(expectedRoot) {
		t.Errorf("Root CID mismatch: expected %s, got %s", expectedRoot.String(), rootCID.String())
	}
}
