package car

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"testing"

	"github.com/LWDJD/ipfar-sdk/verify/ipfs"
	"github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

// knownTestData is the canonical IPFS "hello world" test data.
var knownTestData = []byte("hello world")

// knownRootCID is the CID for the sha256 raw block of "hello world".
// This can be computed: cid.NewCidV1(cid.Raw, multihash.Sum("hello world", SHA2_256, -1))
func computeKnownRootCID(t *testing.T) string {
	t.Helper()
	hash, err := mh.Sum(knownTestData, mh.SHA2_256, -1)
	if err != nil {
		t.Fatalf("failed to compute multihash: %v", err)
	}
	c := cid.NewCidV1(cid.Raw, hash)
	return c.String()
}

func TestBuildCAR_Basic(t *testing.T) {
	rootCID := computeKnownRootCID(t)
	ctx := context.Background()

	carBytes, err := BuildCAR(ctx, knownTestData, rootCID)
	if err != nil {
		t.Fatalf("BuildCAR failed: %v", err)
	}

	if len(carBytes) == 0 {
		t.Fatal("BuildCAR returned empty bytes")
	}

	t.Logf("CAR size: %d bytes", len(carBytes))

	// Write to temp file for parser testing.
	tmpFile, err := os.CreateTemp("", "test_buildcar_*.car")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Write(carBytes)
	tmpFile.Close()

	// Parse the CAR with verify/ipfs.
	parser, err := ipfs.NewCarParserFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to create parser: %v", err)
	}
	defer parser.Close()

	info, err := parser.ParseInfo()
	if err != nil {
		t.Fatalf("failed to parse CAR info: %v", err)
	}

	// Verify version.
	if info.Version != 2 {
		t.Errorf("expected version 2, got %d", info.Version)
	}

	// Verify root CID.
	if len(info.Roots) != 1 {
		t.Fatalf("expected 1 root, got %d", len(info.Roots))
	}
	if info.Roots[0].String() != rootCID {
		t.Errorf("root CID mismatch: expected %s, got %s", rootCID, info.Roots[0].String())
	}

	// Verify data content.
	err = parser.IterateBlocks(func(block *ipfs.Block) error {
		t.Logf("Block: CID=%s, Size=%d", block.CID.String(), len(block.Data))
		if !bytes.Equal(block.Data, knownTestData) {
			t.Errorf("block data mismatch: expected %q, got %q", knownTestData, block.Data)
		}
		// Verify block integrity.
		if err := parser.ValidateBlockIntegrity(block); err != nil {
			t.Errorf("block integrity validation failed: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("IterateBlocks failed: %v", err)
	}

	// Verify index is present.
	hasIndex, err := parser.HasIndex()
	if err != nil {
		t.Fatalf("HasIndex failed: %v", err)
	}
	if !hasIndex {
		t.Error("expected CAR v2 to have an index")
	}
}

func TestBuildCAR_EmptyData(t *testing.T) {
	emptyData := []byte{}

	// CID for empty data: raw codec + sha256 of empty.
	hash := sha256.Sum256(emptyData)
	mhBuf, err := mh.Encode(hash[:], mh.SHA2_256)
	if err != nil {
		t.Fatalf("failed to encode multihash: %v", err)
	}
	rootCID := cid.NewCidV1(cid.Raw, mhBuf).String()

	ctx := context.Background()
	carBytes, err := BuildCAR(ctx, emptyData, rootCID)
	if err != nil {
		t.Fatalf("BuildCAR with empty data failed: %v", err)
	}
	if len(carBytes) == 0 {
		t.Fatal("BuildCAR returned empty bytes for empty data")
	}

	t.Logf("Empty data CAR size: %d bytes", len(carBytes))

	// Parse and verify.
	tmpFile, err := os.CreateTemp("", "test_buildcar_empty_*.car")
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
	if len(info.Roots) != 1 {
		t.Fatalf("expected 1 root, got %d", len(info.Roots))
	}
	if info.Roots[0].String() != rootCID {
		t.Errorf("root CID mismatch: expected %s, got %s", rootCID, info.Roots[0].String())
	}

	// Check block.
	err = parser.IterateBlocks(func(block *ipfs.Block) error {
		if len(block.Data) != 0 {
			t.Errorf("expected empty block data, got %d bytes", len(block.Data))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("IterateBlocks failed: %v", err)
	}
}

func TestBuildCAR_SmallData(t *testing.T) {
	smallData := []byte("A")

	hash, err := mh.Sum(smallData, mh.SHA2_256, -1)
	if err != nil {
		t.Fatalf("failed to compute multihash: %v", err)
	}
	rootCID := cid.NewCidV1(cid.Raw, hash).String()

	ctx := context.Background()
	carBytes, err := BuildCAR(ctx, smallData, rootCID)
	if err != nil {
		t.Fatalf("BuildCAR failed: %v", err)
	}

	t.Logf("Small data CAR size: %d bytes", len(carBytes))

	// Parse.
	tmpFile, err := os.CreateTemp("", "test_buildcar_small_*.car")
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

	// Verify block data.
	var found bool
	err = parser.IterateBlocks(func(block *ipfs.Block) error {
		found = true
		if !bytes.Equal(block.Data, smallData) {
			t.Errorf("block data mismatch: expected %q, got %q", smallData, block.Data)
		}
		if err := parser.ValidateBlockIntegrity(block); err != nil {
			t.Errorf("block integrity validation failed: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("IterateBlocks failed: %v", err)
	}
	if !found {
		t.Error("no blocks found in CAR")
	}
}

func TestBuildCAR_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := BuildCAR(ctx, []byte("test"), "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")
	if err == nil {
		t.Fatal("expected error with cancelled context")
	}
	t.Logf("Got expected error: %v", err)
}

func TestBuildCAR_InvalidCID(t *testing.T) {
	ctx := context.Background()
	_, err := BuildCAR(ctx, []byte("test"), "not-a-valid-cid")
	if err == nil {
		t.Fatal("expected error with invalid CID")
	}
	t.Logf("Got expected error: %v", err)
}

func TestBuildCAR_LargerData(t *testing.T) {
	// ~10 KB of data.
	largerData := bytes.Repeat([]byte("IPFAR-CAR-TEST-DATA-"), 500)
	hash, err := mh.Sum(largerData, mh.SHA2_256, -1)
	if err != nil {
		t.Fatalf("failed to compute multihash: %v", err)
	}
	rootCID := cid.NewCidV1(cid.Raw, hash).String()

	ctx := context.Background()
	carBytes, err := BuildCAR(ctx, largerData, rootCID)
	if err != nil {
		t.Fatalf("BuildCAR failed: %v", err)
	}

	t.Logf("Larger data CAR size: %d bytes (data: %d bytes)", len(carBytes), len(largerData))

	// Parse and verify.
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

	err = parser.IterateBlocks(func(block *ipfs.Block) error {
		if !bytes.Equal(block.Data, largerData) {
			t.Errorf("block data mismatch")
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
