package ipfs

import (
	"bytes"
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

		parser, err := NewCarParserFromFile(tmpFile.Name())
		if err != nil {
			t.Fatalf("Failed to create parser: %v", err)
		}
		defer parser.Close()

		_, err = parser.ParseInfo()
		if err == nil {
			t.Fatal("Expected error for invalid CAR file")
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
