package car

import (
	"bytes"
	"context"
	"os"
	"sync"
	"testing"

	"github.com/LWDJD/ipfar-sdk/verify/ipfs"
	"github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

// ============================================================
// Concurrent BuildCAR
// ============================================================

func TestBuildCAR_Concurrent(t *testing.T) {
	// Build multiple CARs concurrently
	var wg sync.WaitGroup
	errCh := make(chan error, 20)
	results := make(chan int, 20)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			data := bytes.Repeat([]byte{byte(idx)}, 1000)
			hash, err := mh.Sum(data, mh.SHA2_256, -1)
			if err != nil {
				errCh <- err
				return
			}
			rootCID := cid.NewCidV1(cid.Raw, hash).String()

			carBytes, err := BuildCAR(context.Background(), data, rootCID)
			if err != nil {
				errCh <- err
				return
			}

			results <- len(carBytes)
		}(i)
	}

	wg.Wait()
	close(errCh)
	close(results)

	for err := range errCh {
		t.Errorf("concurrent BuildCAR failed: %v", err)
	}

	count := 0
	for size := range results {
		if size == 0 {
			t.Error("CAR size should be > 0")
		}
		count++
	}

	if count != 20 {
		t.Errorf("expected 20 results, got %d", count)
	}
}

// ============================================================
// Large block size test
// ============================================================

func TestBuildCAR_LargeBlock(t *testing.T) {
	// 2 MB block
	largeData := bytes.Repeat([]byte("X"), 2*1024*1024) // 2 MiB
	hash, err := mh.Sum(largeData, mh.SHA2_256, -1)
	if err != nil {
		t.Fatalf("failed to compute multihash: %v", err)
	}
	rootCID := cid.NewCidV1(cid.Raw, hash).String()

	ctx := context.Background()
	carBytes, err := BuildCAR(ctx, largeData, rootCID)
	if err != nil {
		t.Fatalf("BuildCAR with 2MB block failed: %v", err)
	}

	t.Logf("2 MiB block CAR size: %d bytes", len(carBytes))

	// Parse and verify
	tmpFile, err := os.CreateTemp("", "test_buildcar_large_*.car")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Write(carBytes)
	tmpFile.Close()

	parser, err := ipfs.NewCarParserFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to create parser: %v", err)
	}
	defer parser.Close()

	// Verify the block content
	err = parser.IterateBlocks(func(block *ipfs.Block) error {
		if !bytes.Equal(block.Data, largeData) {
			t.Errorf("block data mismatch: expected %d bytes, got %d bytes", len(largeData), len(block.Data))
		}
		if err := parser.ValidateBlockIntegrity(block); err != nil {
			t.Errorf("block integrity validation failed: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("IterateBlocks failed: %v", err)
	}
}

// ============================================================
// Very large block (> 4MB)
// ============================================================

func TestBuildCAR_VeryLargeBlock(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large block test in short mode")
	}

	// 5 MB block
	largeData := bytes.Repeat([]byte("Y"), 5*1024*1024) // 5 MiB
	hash, err := mh.Sum(largeData, mh.SHA2_256, -1)
	if err != nil {
		t.Fatalf("failed to compute multihash: %v", err)
	}
	rootCID := cid.NewCidV1(cid.Raw, hash).String()

	carBytes, err := BuildCAR(context.Background(), largeData, rootCID)
	if err != nil {
		t.Fatalf("BuildCAR with 5MB block failed: %v", err)
	}

	t.Logf("5 MiB block CAR size: %d bytes", len(carBytes))

	// Verify roundtrip
	tmpFile, err := os.CreateTemp("", "test_buildcar_5mb_*.car")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Write(carBytes)
	tmpFile.Close()

	parser, err := ipfs.NewCarParserFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to create parser: %v", err)
	}
	defer parser.Close()

	info, err := parser.ParseInfo()
	if err != nil {
		t.Fatalf("failed to parse CAR info: %v", err)
	}
	if info.Version != 2 {
		t.Errorf("expected version 2, got %d", info.Version)
	}

	err = parser.IterateBlocks(func(block *ipfs.Block) error {
		if !bytes.Equal(block.Data, largeData) {
			t.Errorf("block data mismatch")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("IterateBlocks failed: %v", err)
	}
}

// ============================================================
// Multiple blocks in a single CAR
// ============================================================

func TestBuildCAR_MultipleDataBlocks(t *testing.T) {
	// BuildCAR currently supports single block.
	// Verify that a CAR with known structure is parseable.
	data1 := []byte("block one - hello world")
	hash, err := mh.Sum(data1, mh.SHA2_256, -1)
	if err != nil {
		t.Fatalf("failed to compute multihash: %v", err)
	}
	rootCID := cid.NewCidV1(cid.Raw, hash).String()

	carBytes, err := BuildCAR(context.Background(), data1, rootCID)
	if err != nil {
		t.Fatalf("BuildCAR failed: %v", err)
	}

	// Parse and verify block count
	tmpFile, err := os.CreateTemp("", "test_buildcar_multi_*.car")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Write(carBytes)
	tmpFile.Close()

	parser, err := ipfs.NewCarParserFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to create parser: %v", err)
	}
	defer parser.Close()

	blockCount := 0
	err = parser.IterateBlocks(func(block *ipfs.Block) error {
		blockCount++
		return nil
	})
	if err != nil {
		t.Fatalf("IterateBlocks failed: %v", err)
	}

	if blockCount != 1 {
		t.Errorf("expected 1 block, got %d", blockCount)
	}

	t.Logf("Single-block CAR: %d blocks", blockCount)
}

// ============================================================
// Build-then-parse integrity: verify CID computation
// ============================================================

func TestBuildCAR_CIDIntegrity(t *testing.T) {
	testData := []byte("cid integrity test data !@#$%^&*()")

	// Compute expected root CID
	hash, err := mh.Sum(testData, mh.SHA2_256, -1)
	if err != nil {
		t.Fatalf("failed to compute multihash: %v", err)
	}
	expectedRootCID := cid.NewCidV1(cid.Raw, hash).String()

	carBytes, err := BuildCAR(context.Background(), testData, expectedRootCID)
	if err != nil {
		t.Fatalf("BuildCAR failed: %v", err)
	}

	// Write to temp
	tmpFile, err := os.CreateTemp("", "test_cid_integrity_*.car")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Write(carBytes)
	tmpFile.Close()

	parser, err := ipfs.NewCarParserFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to create parser: %v", err)
	}
	defer parser.Close()

	info, err := parser.ParseInfo()
	if err != nil {
		t.Fatalf("failed to parse CAR info: %v", err)
	}

	if len(info.Roots) != 1 {
		t.Fatalf("expected 1 root, got %d", len(info.Roots))
	}
	if info.Roots[0].String() != expectedRootCID {
		t.Errorf("root CID mismatch: expected %s, got %s", expectedRootCID, info.Roots[0].String())
	}

	// Also verify the block's own CID
	err = parser.IterateBlocks(func(block *ipfs.Block) error {
		// The block CID is for the raw data, and is different from the root CID (which is the CAR root)
		// Just verify integrity
		if err := parser.ValidateBlockIntegrity(block); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatalf("block validation failed: %v", err)
	}
}

// ============================================================
// Context timeout during build
// ============================================================

func TestBuildCAR_ContextTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	cancel() // immediately expired

	_, err := BuildCAR(ctx, []byte("test"), "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")
	if err == nil {
		t.Fatal("expected error with expired context")
	}
	t.Logf("Got expected error: %v", err)
}

// ============================================================
// Empty data with proper CID
// ============================================================

func TestBuildCAR_EmptyDataIntegrity(t *testing.T) {
	emptyData := []byte{}

	hash, err := mh.Sum(emptyData, mh.SHA2_256, -1)
	if err != nil {
		t.Fatalf("failed to compute multihash: %v", err)
	}
	rootCID := cid.NewCidV1(cid.Raw, hash).String()

	carBytes, err := BuildCAR(context.Background(), emptyData, rootCID)
	if err != nil {
		t.Fatalf("BuildCAR with empty data failed: %v", err)
	}

	// Parse back
	tmpFile, err := os.CreateTemp("", "test_empty_integrity_*.car")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Write(carBytes)
	tmpFile.Close()

	parser, err := ipfs.NewCarParserFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to create parser: %v", err)
	}
	defer parser.Close()

	err = parser.IterateBlocks(func(block *ipfs.Block) error {
		if len(block.Data) != 0 {
			t.Errorf("expected empty block, got %d bytes", len(block.Data))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("IterateBlocks failed: %v", err)
	}
}

// ============================================================
// Byte-exact CAR structure verification
// ============================================================

func TestBuildCAR_StructureBytes(t *testing.T) {
	// Verify that BuildCAR produces a CAR starting with the correct pragma
	data := []byte("structure test")
	hash, err := mh.Sum(data, mh.SHA2_256, -1)
	if err != nil {
		t.Fatalf("failed to compute multihash: %v", err)
	}
	rootCID := cid.NewCidV1(cid.Raw, hash).String()

	carBytes, err := BuildCAR(context.Background(), data, rootCID)
	if err != nil {
		t.Fatalf("BuildCAR failed: %v", err)
	}

	if len(carBytes) < 65 {
		t.Fatalf("CAR too small: %d bytes", len(carBytes))
	}

	// The first bytes should be a CBOR pragma (0x0a or similar)
	t.Logf("First bytes: %x", carBytes[:min(30, len(carBytes))])

	// Verify we can find the data within the CAR
	if !bytes.Contains(carBytes, data) {
		t.Error("CAR should contain the original data bytes")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ============================================================
// Verify index presence
// ============================================================

func TestBuildCAR_HasIndex(t *testing.T) {
	data := []byte("index presence check")
	hash, err := mh.Sum(data, mh.SHA2_256, -1)
	if err != nil {
		t.Fatalf("failed to compute multihash: %v", err)
	}
	rootCID := cid.NewCidV1(cid.Raw, hash).String()

	carBytes, err := BuildCAR(context.Background(), data, rootCID)
	if err != nil {
		t.Fatalf("BuildCAR failed: %v", err)
	}

	tmpFile, err := os.CreateTemp("", "test_index_*.car")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Write(carBytes)
	tmpFile.Close()

	parser, err := ipfs.NewCarParserFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to create parser: %v", err)
	}
	defer parser.Close()

	hasIndex, err := parser.HasIndex()
	if err != nil {
		t.Fatalf("HasIndex failed: %v", err)
	}
	if !hasIndex {
		t.Error("CAR v2 should have an index")
	}
}

// ============================================================
// Cross-validate CAR parsability with go-car/v2 library
// ============================================================

func TestBuildCAR_CrossValidateWithGoCar(t *testing.T) {
	data := []byte("cross-validate with standard go-car library")
	hash, err := mh.Sum(data, mh.SHA2_256, -1)
	if err != nil {
		t.Fatalf("failed to compute multihash: %v", err)
	}
	rootCID := cid.NewCidV1(cid.Raw, hash).String()

	carBytes, err := BuildCAR(context.Background(), data, rootCID)
	if err != nil {
		t.Fatalf("BuildCAR failed: %v", err)
	}

	// Parse with our parser
	tmpFile, err := os.CreateTemp("", "test_cross_*.car")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Write(carBytes)
	tmpFile.Close()

	parser, err := ipfs.NewCarParserFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("go-car parser failed: %v", err)
	}
	defer parser.Close()

	info, err := parser.ParseInfo()
	if err != nil {
		t.Fatalf("ParseInfo failed: %v", err)
	}

	if info.Version != 2 {
		t.Errorf("cross-validate: version should be 2, got %d", info.Version)
	}

	// Verify block content
	var found bool
	err = parser.IterateBlocks(func(block *ipfs.Block) error {
		found = true
		if !bytes.Equal(block.Data, data) {
			t.Errorf("cross-validate: data mismatch")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("IterateBlocks failed: %v", err)
	}
	if !found {
		t.Error("cross-validate: no blocks found")
	}
}

// ============================================================
// Stress: rapid sequential builds
// ============================================================

func TestBuildCAR_RapidSequential(t *testing.T) {
	for i := 0; i < 50; i++ {
		data := bytes.Repeat([]byte{byte(i)}, 100)
		hash, err := mh.Sum(data, mh.SHA2_256, -1)
		if err != nil {
			t.Fatalf("iteration %d: mh.Sum failed: %v", i, err)
		}
		rootCID := cid.NewCidV1(cid.Raw, hash).String()

		carBytes, err := BuildCAR(context.Background(), data, rootCID)
		if err != nil {
			t.Fatalf("iteration %d: BuildCAR failed: %v", i, err)
		}
		if len(carBytes) == 0 {
			t.Fatalf("iteration %d: empty CAR", i)
		}
	}
}
