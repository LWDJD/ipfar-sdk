package ipfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"testing"

	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
)

func TestCarParser(t *testing.T) {
	t.Run("ParseNonExistentFile", func(t *testing.T) {
		_, err := NewCarParserFromFile("nonexistent.car")
		if err == nil {
			t.Fatal("Expected error for non-existent file")
		}
		t.Logf("Got expected error: %v", err)
	})

	t.Run("ParseInvalidFile", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "invalid_*.car")
		if err != nil {
			t.Fatalf("Failed to create temp file: %v", err)
		}
		defer os.Remove(tmpFile.Name())

		tmpFile.Write([]byte("invalid car data"))
		tmpFile.Close()

		// New parser now validates early; expect creation to fail for invalid data.
		_, err = NewCarParserFromFile(tmpFile.Name())
		if err == nil {
			t.Fatal("Expected error creating parser for invalid CAR file")
		}
		t.Logf("Got expected error: %v", err)
	})

	t.Run("ValidateMultihash", func(t *testing.T) {
		mh, err := multihash.Sum([]byte("test data"), multihash.SHA2_256, -1)
		if err != nil {
			t.Fatalf("Failed to create multihash: %v", err)
		}

		err = ValidateMultihash(mh)
		if err != nil {
			t.Fatalf("Failed to validate multihash: %v", err)
		}

		err = ValidateMultihash(nil)
		if err == nil {
			t.Fatal("Expected error for nil multihash")
		}
		t.Logf("Got expected error for nil multihash: %v", err)
	})
}

func TestCarParserWithRealFile(t *testing.T) {
	testFile := "test.car"

	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Skipf("Skipping test: %s not found", testFile)
	}

	parser, err := NewCarParserFromFile(testFile)
	if err != nil {
		t.Fatalf("Failed to create parser: %v", err)
	}
	defer parser.Close()

	t.Run("ParseInfo", func(t *testing.T) {
		info, err := parser.ParseInfo()
		if err != nil {
			t.Fatalf("Failed to parse info: %v", err)
		}

		fmt.Printf("CAR Version: %d\n", info.Version)
		fmt.Printf("Root CIDs: %d\n", len(info.Roots))
		for i, root := range info.Roots {
			fmt.Printf("  Root %d: %s\n", i, root.String())
		}
		fmt.Printf("Data Offset: %d\n", info.DataOffset)
		fmt.Printf("Data Size: %d\n", info.DataSize)
		fmt.Printf("Has Index: %v\n", info.HasIndex)
		fmt.Printf("File Size: %d\n", info.FileSize)
	})

	t.Run("GetRootCID", func(t *testing.T) {
		rootCID, err := parser.GetRootCID()
		if err != nil {
			t.Fatalf("Failed to get root CID: %v", err)
		}
		fmt.Printf("Root CID: %s\n", rootCID.String())
	})

	t.Run("ValidateRoots", func(t *testing.T) {
		roots, err := parser.GetRootCIDs()
		if err != nil {
			t.Fatalf("Failed to get root CIDs: %v", err)
		}

		err = parser.ValidateRoots(roots)
		if err != nil {
			t.Fatalf("Root validation failed: %v", err)
		}
		t.Log("Root validation passed")
	})

	t.Run("ValidateIndex", func(t *testing.T) {
		isV2, err := parser.IsCarV2()
		if err != nil {
			t.Fatalf("Failed to check CAR version: %v", err)
		}

		if isV2 {
			err = parser.ValidateIndex()
			if err != nil {
				t.Logf("Index validation result: %v", err)
			} else {
				t.Log("Index validation passed")
			}
		} else {
			t.Skip("Skipping index validation for CARv1")
		}
	})

	t.Run("IterateBlocks", func(t *testing.T) {
		blockCount := 0
		totalSize := uint64(0)

		err := parser.IterateBlocks(func(block *Block) error {
			blockCount++
			totalSize += uint64(len(block.Data))

			if blockCount <= 3 {
				fmt.Printf("Block %d: CID=%s, Size=%d\n", blockCount, block.CID.String(), len(block.Data))
			}

			return nil
		})

		if err != nil {
			t.Fatalf("Failed to iterate blocks: %v", err)
		}

		fmt.Printf("Total blocks: %d, Total size: %d bytes\n", blockCount, totalSize)
	})

	t.Run("FindBlockByRootCID", func(t *testing.T) {
		rootCID, err := parser.GetRootCID()
		if err != nil {
			t.Fatalf("Failed to get root CID: %v", err)
		}

		block, metadata, err := parser.findBlockByCID(rootCID)
		if err != nil {
			t.Logf("Block not found (expected for some CAR files): %v", err)
			return
		}

		fmt.Printf("Found block: CID=%s\n", block.CID.String())
		fmt.Printf("Metadata: Offset=%d, Size=%d\n", metadata.Offset, metadata.Size)

		err = parser.ValidateBlockIntegrity(block)
		if err != nil {
			t.Fatalf("Block integrity validation failed: %v", err)
		}
		t.Log("Block integrity validation passed")
	})
}

func TestCarV2Header(t *testing.T) {
	v2Pragma := []byte{0x63, 0x61, 0x72, 0x02}
	header := make([]byte, 4)
	copy(header, v2Pragma)

	if !bytes.Equal(header[:4], carv2Pragma) {
		t.Fatal("CARv2 pragma mismatch")
	}

	t.Log("CARv2 pragma detection works correctly")
}

func TestCIDOperations(t *testing.T) {
	mh, err := multihash.Sum([]byte("test"), multihash.SHA2_256, -1)
	if err != nil {
		t.Fatalf("Failed to create multihash: %v", err)
	}

	testCID := cid.NewCidV1(cid.Raw, mh)

	t.Run("CIDEquals", func(t *testing.T) {
		if !testCID.Equals(testCID) {
			t.Fatal("CID should equal itself")
		}
	})

	t.Run("CIDByteLen", func(t *testing.T) {
		byteLen := testCID.ByteLen()
		if byteLen <= 0 {
			t.Fatal("CID byte length should be positive")
		}
		t.Logf("CID byte length: %d", byteLen)
	})

	t.Run("CIDPrefix", func(t *testing.T) {
		prefix := testCID.Prefix()
		t.Logf("CID prefix: version=%d, codec=%d, hash=%d, length=%d",
			prefix.Version, prefix.Codec, prefix.MhType, prefix.MhLength)
	})
}

// =============================================================================
// NewCarParserFromReader tests
// =============================================================================

func TestNewCarParserFromReader_UnitTest(t *testing.T) {
	t.Run("ValidReader", func(t *testing.T) {
		data := []byte{0x01, 0x00, 0x00, 0x00} // minimal CARv1: version=1, roots=0, padded to 4+ bytes
		reader := bytes.NewReader(data)
		parser, err := NewCarParserFromReader(reader, int64(len(data)))
		if err != nil {
			t.Fatalf("NewCarParserFromReader failed: %v", err)
		}
		if parser == nil {
			t.Fatal("expected non-nil parser")
		}
		if parser.GetFileSize() != int64(len(data)) {
			t.Errorf("expected file size %d, got %d", len(data), parser.GetFileSize())
		}
	})

	t.Run("NilReader", func(t *testing.T) {
		_, err := NewCarParserFromReader(nil, 100)
		if err == nil {
			t.Fatal("expected error for nil reader")
		}
	})

	t.Run("InvalidSize", func(t *testing.T) {
		data := []byte{0x01}
		reader := bytes.NewReader(data)
		_, err := NewCarParserFromReader(reader, 0)
		if err == nil {
			t.Fatal("expected error for zero size")
		}
		_, err = NewCarParserFromReader(reader, -1)
		if err == nil {
			t.Fatal("expected error for negative size")
		}
	})
}

// =============================================================================
// parseCarV1Info / readCarV1Header tests with constructed CAR v1 data
// =============================================================================

func TestParseCarV1Info_UnitTest(t *testing.T) {
	// Construct a valid CARv1 file with version=1 and one root CID
	mh, _ := multihash.Sum([]byte("block1"), multihash.SHA2_256, -1)
	rootCID := cid.NewCidV1(cid.Raw, mh)

	var buf bytes.Buffer
	// version=1 as varint
	verBuf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(verBuf, 1)
	buf.Write(verBuf[:n])
	// root count=1
	cntBuf := make([]byte, binary.MaxVarintLen64)
	n = binary.PutUvarint(cntBuf, 1)
	buf.Write(cntBuf[:n])
	// CID length
	rootBytes := rootCID.Bytes()
	lenBuf := make([]byte, binary.MaxVarintLen64)
	n = binary.PutUvarint(lenBuf, uint64(len(rootBytes)))
	buf.Write(lenBuf[:n])
	buf.Write(rootBytes)
	// Add a dummy block
	blockData := []byte("hello")
	blockCIDBytes := rootCID.Bytes()
	sectionLen := uint64(len(blockCIDBytes) + len(blockData))
	slBuf := make([]byte, binary.MaxVarintLen64)
	n = binary.PutUvarint(slBuf, sectionLen)
	buf.Write(slBuf[:n])
	buf.Write(blockCIDBytes)
	buf.Write(blockData)

	carData := buf.Bytes()
	reader := bytes.NewReader(carData)
	parser, err := NewCarParserFromReader(reader, int64(len(carData)))
	if err != nil {
		t.Fatalf("NewCarParserFromReader failed: %v", err)
	}

	info, err := parser.ParseInfo()
	if err != nil {
		t.Fatalf("ParseInfo failed: %v", err)
	}

	if info.Version != 1 {
		t.Errorf("expected version 1, got %d", info.Version)
	}
	if len(info.Roots) != 1 {
		t.Errorf("expected 1 root, got %d", len(info.Roots))
	}
	if !info.Roots[0].Equals(rootCID) {
		t.Errorf("root CID mismatch")
	}
	if info.HasIndex {
		t.Error("CARv1 should not have index")
	}
	t.Logf("CARv1 parsed: version=%d, roots=%d, dataOffset=%d, dataSize=%d",
		info.Version, len(info.Roots), info.DataOffset, info.DataSize)
}

func TestReadCarV1Header_UnitTest(t *testing.T) {
	// Construct CARv1 header with 2 root CIDs
	mh1, _ := multihash.Sum([]byte("data1"), multihash.SHA2_256, -1)
	cid1 := cid.NewCidV1(cid.Raw, mh1)
	mh2, _ := multihash.Sum([]byte("data2"), multihash.SHA2_256, -1)
	cid2 := cid.NewCidV1(cid.Raw, mh2)

	var buf bytes.Buffer
	verBuf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(verBuf, 1)
	buf.Write(verBuf[:n])
	cntBuf := make([]byte, binary.MaxVarintLen64)
	n = binary.PutUvarint(cntBuf, 2)
	buf.Write(cntBuf[:n])
	for _, c := range []cid.Cid{cid1, cid2} {
		cb := c.Bytes()
		lb := make([]byte, binary.MaxVarintLen64)
		n = binary.PutUvarint(lb, uint64(len(cb)))
		buf.Write(lb[:n])
		buf.Write(cb)
	}

	carData := buf.Bytes()
	reader := bytes.NewReader(carData)
	parser, err := NewCarParserFromReader(reader, int64(len(carData)))
	if err != nil {
		t.Fatalf("NewCarParserFromReader failed: %v", err)
	}

	headerSize, roots, err := parser.readCarV1Header()
	if err != nil {
		t.Fatalf("readCarV1Header failed: %v", err)
	}

	if headerSize == 0 {
		t.Error("header size should not be 0")
	}
	if len(roots) != 2 {
		t.Errorf("expected 2 roots, got %d", len(roots))
	}
	if !roots[0].Equals(cid1) || !roots[1].Equals(cid2) {
		t.Error("root CID mismatch")
	}
	t.Logf("CARv1 header: size=%d, roots=%d", headerSize, len(roots))
}

// =============================================================================
// ValidateRoots tests
// =============================================================================

func TestValidateRoots_UnitTest(t *testing.T) {
	mh, _ := multihash.Sum([]byte("block1"), multihash.SHA2_256, -1)
	rootCID := cid.NewCidV1(cid.Raw, mh)

	// Build a minimal CARv1 with one root
	var buf bytes.Buffer
	verBuf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(verBuf, 1)
	buf.Write(verBuf[:n])
	cntBuf := make([]byte, binary.MaxVarintLen64)
	n = binary.PutUvarint(cntBuf, 1)
	buf.Write(cntBuf[:n])
	rootBytes := rootCID.Bytes()
	lenBuf := make([]byte, binary.MaxVarintLen64)
	n = binary.PutUvarint(lenBuf, uint64(len(rootBytes)))
	buf.Write(lenBuf[:n])
	buf.Write(rootBytes)

	carData := buf.Bytes()
	reader := bytes.NewReader(carData)
	parser, err := NewCarParserFromReader(reader, int64(len(carData)))
	if err != nil {
		t.Fatalf("NewCarParserFromReader failed: %v", err)
	}

	t.Run("MatchingRoots", func(t *testing.T) {
		err := parser.ValidateRoots([]cid.Cid{rootCID})
		if err != nil {
			t.Errorf("expected validation to pass, got: %v", err)
		}
	})

	t.Run("WrongRootCount", func(t *testing.T) {
		err := parser.ValidateRoots([]cid.Cid{rootCID, rootCID})
		if err == nil {
			t.Fatal("expected error for wrong root count")
		}
		t.Logf("Got expected error: %v", err)
	})

	t.Run("DifferentRoot", func(t *testing.T) {
		mh2, _ := multihash.Sum([]byte("other"), multihash.SHA2_256, -1)
		otherCID := cid.NewCidV1(cid.Raw, mh2)
		err := parser.ValidateRoots([]cid.Cid{otherCID})
		if err == nil {
			t.Fatal("expected error for different root CID")
		}
		t.Logf("Got expected error: %v", err)
	})
}

// =============================================================================
// ValidateIndex tests
// =============================================================================

func TestValidateIndex_UnitTest(t *testing.T) {
	t.Run("CARv1IndexValidation", func(t *testing.T) {
		data := []byte{0x01, 0x00, 0x00, 0x00} // minimal CARv1: version=1, roots=0
		reader := bytes.NewReader(data)
		parser, err := NewCarParserFromReader(reader, int64(len(data)))
		if err != nil {
			t.Fatalf("NewCarParserFromReader failed: %v", err)
		}
		err = parser.ValidateIndex()
		if err == nil {
			t.Fatal("expected error for CARv1 index validation")
		}
		t.Logf("Got expected error for CARv1: %v", err)
	})
}

// =============================================================================
// GetBlockMetadata tests
// =============================================================================

func TestGetBlockMetadata_UnitTest(t *testing.T) {
	mh, _ := multihash.Sum([]byte("block1"), multihash.SHA2_256, -1)
	rootCID := cid.NewCidV1(cid.Raw, mh)

	blockData := []byte("test block data")

	var buf bytes.Buffer
	// CARv1 header
	verBuf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(verBuf, 1)
	buf.Write(verBuf[:n])
	cntBuf := make([]byte, binary.MaxVarintLen64)
	n = binary.PutUvarint(cntBuf, 1)
	buf.Write(cntBuf[:n])
	rootBytes := rootCID.Bytes()
	lenBuf := make([]byte, binary.MaxVarintLen64)
	n = binary.PutUvarint(lenBuf, uint64(len(rootBytes)))
	buf.Write(lenBuf[:n])
	buf.Write(rootBytes)
	// Block section
	cidBytes := rootCID.Bytes()
	sectionLen := uint64(len(cidBytes) + len(blockData))
	slBuf := make([]byte, binary.MaxVarintLen64)
	n = binary.PutUvarint(slBuf, sectionLen)
	buf.Write(slBuf[:n])
	buf.Write(cidBytes)
	buf.Write(blockData)

	carData := buf.Bytes()
	reader := bytes.NewReader(carData)
	parser, err := NewCarParserFromReader(reader, int64(len(carData)))
	if err != nil {
		t.Fatalf("NewCarParserFromReader failed: %v", err)
	}

	meta, err := parser.GetBlockMetadata(rootCID)
	if err != nil {
		t.Fatalf("GetBlockMetadata failed: %v", err)
	}
	if !meta.CID.Equals(rootCID) {
		t.Errorf("CID mismatch in metadata")
	}
	if meta.Size != uint64(len(blockData)) {
		t.Errorf("expected size %d, got %d", len(blockData), meta.Size)
	}
	t.Logf("BlockMetadata: CID=%s, Offset=%d, Size=%d", meta.CID.String(), meta.Offset, meta.Size)
}

// =============================================================================
// GetRootCIDs / IsCarV2 / HasIndex / GetFileSize / GetInfo tests
// =============================================================================

func TestGetRootCIDs_UnitTest(t *testing.T) {
	mh, _ := multihash.Sum([]byte("block1"), multihash.SHA2_256, -1)
	rootCID := cid.NewCidV1(cid.Raw, mh)

	var buf bytes.Buffer
	verBuf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(verBuf, 1)
	buf.Write(verBuf[:n])
	cntBuf := make([]byte, binary.MaxVarintLen64)
	n = binary.PutUvarint(cntBuf, 1)
	buf.Write(cntBuf[:n])
	rootBytes := rootCID.Bytes()
	lenBuf := make([]byte, binary.MaxVarintLen64)
	n = binary.PutUvarint(lenBuf, uint64(len(rootBytes)))
	buf.Write(lenBuf[:n])
	buf.Write(rootBytes)

	carData := buf.Bytes()
	reader := bytes.NewReader(carData)
	parser, err := NewCarParserFromReader(reader, int64(len(carData)))
	if err != nil {
		t.Fatalf("NewCarParserFromReader failed: %v", err)
	}

	roots, err := parser.GetRootCIDs()
	if err != nil {
		t.Fatalf("GetRootCIDs failed: %v", err)
	}
	if len(roots) != 1 {
		t.Errorf("expected 1 root, got %d", len(roots))
	}
	if !roots[0].Equals(rootCID) {
		t.Error("root CID mismatch")
	}
}

func TestIsCarV2_UnitTest(t *testing.T) {
	t.Run("CARv1", func(t *testing.T) {
		data := []byte{0x01, 0x00, 0x00, 0x00}
		reader := bytes.NewReader(data)
		parser, _ := NewCarParserFromReader(reader, int64(len(data)))
		isV2, err := parser.IsCarV2()
		if err != nil {
			t.Fatalf("IsCarV2 failed: %v", err)
		}
		if isV2 {
			t.Error("CARv1 should not be identified as CARv2")
		}
	})

	t.Run("CARv2", func(t *testing.T) {
		// Minimal CARv2: pragma + header with data pointing to a CARv1 inside
		var buf bytes.Buffer
		buf.Write(carv2Pragma)
		v2Header := make([]byte, 48)
		// DataOffset = 52 (4 pragma + 48 header)
		binary.LittleEndian.PutUint64(v2Header[16:24], 52)
		binary.LittleEndian.PutUint64(v2Header[24:32], 2)   // data size (minimal v1)
		binary.LittleEndian.PutUint64(v2Header[32:40], 54)  // index offset (after data)
		binary.LittleEndian.PutUint64(v2Header[40:48], 4)   // index size
		buf.Write(v2Header)
		// Inner CARv1: version=1, roots=0
		buf.Write([]byte{0x01, 0x00, 0x00, 0x00})
		// Index placeholder
		buf.Write([]byte{0x00, 0x00, 0x00, 0x00})

		carData := buf.Bytes()
		reader := bytes.NewReader(carData)
		parser, _ := NewCarParserFromReader(reader, int64(len(carData)))
		isV2, err := parser.IsCarV2()
		if err != nil {
			t.Fatalf("IsCarV2 failed: %v", err)
		}
		if !isV2 {
			t.Error("CARv2 should be identified as CARv2")
		}
	})
}

func TestHasIndex_UnitTest(t *testing.T) {
	t.Run("CARv1", func(t *testing.T) {
		data := []byte{0x01, 0x00, 0x00, 0x00}
		reader := bytes.NewReader(data)
		parser, _ := NewCarParserFromReader(reader, int64(len(data)))
		hasIdx, err := parser.HasIndex()
		if err != nil {
			t.Fatalf("HasIndex failed: %v", err)
		}
		if hasIdx {
			t.Error("CARv1 should not have index")
		}
	})

	t.Run("CARv2WithIndex", func(t *testing.T) {
		var buf bytes.Buffer
		buf.Write(carv2Pragma)
		v2Header := make([]byte, 48)
		binary.LittleEndian.PutUint64(v2Header[16:24], 52)
		binary.LittleEndian.PutUint64(v2Header[24:32], 2)
		binary.LittleEndian.PutUint64(v2Header[32:40], 54)
		binary.LittleEndian.PutUint64(v2Header[40:48], 4)
		buf.Write(v2Header)
		buf.Write([]byte{0x01, 0x00, 0x00, 0x00})
		buf.Write([]byte{0x00, 0x00, 0x00, 0x00})

		carData := buf.Bytes()
		reader := bytes.NewReader(carData)
		parser, _ := NewCarParserFromReader(reader, int64(len(carData)))
		hasIdx, err := parser.HasIndex()
		if err != nil {
			t.Fatalf("HasIndex failed: %v", err)
		}
		if !hasIdx {
			t.Error("CARv2 with index should report HasIndex=true")
		}
	})
}

func TestGetFileSize_UnitTest(t *testing.T) {
	data := []byte{0x01, 0x00, 0x03, 0x04}
	reader := bytes.NewReader(data)
	parser, err := NewCarParserFromReader(reader, int64(len(data)))
	if err != nil {
		t.Fatalf("NewCarParserFromReader failed: %v", err)
	}
	if parser.GetFileSize() != int64(len(data)) {
		t.Errorf("expected file size %d, got %d", len(data), parser.GetFileSize())
	}
}

func TestGetInfo_UnitTest(t *testing.T) {
	data := []byte{0x01, 0x00, 0x00, 0x00}
	reader := bytes.NewReader(data)
	parser, err := NewCarParserFromReader(reader, int64(len(data)))
	if err != nil {
		t.Fatalf("NewCarParserFromReader failed: %v", err)
	}

	// GetInfo should trigger parsing on first call
	info, err := parser.GetInfo()
	if err != nil {
		t.Fatalf("GetInfo failed: %v", err)
	}
	if info.Version != 1 {
		t.Errorf("expected version 1, got %d", info.Version)
	}
	if info.FileSize != int64(len(data)) {
		t.Errorf("expected file size %d, got %d", len(data), info.FileSize)
	}

	// Second call should return cached info
	info2, err := parser.GetInfo()
	if err != nil {
		t.Fatalf("GetInfo (cached) failed: %v", err)
	}
	if info != info2 {
		t.Error("GetInfo should return same pointer on second call")
	}
}
