// Command ipfar-pow is a standalone CLI tool for IPFAR Proof-of-Work
// computation, verification, benchmarking, and testing.
//
// Usage:
//
//	ipfar-pow compute --root-cid <cid> --data-txid <txid> [--workers 10] [--timeout 300] [--difficulty 2]
//	ipfar-pow verify  --root-cid <cid> --data-txid <txid> --salt <salt> [--difficulty 2]
//	ipfar-pow bench   [--workers 4] [--duration 30]
//	ipfar-pow test    [--workers 10]
package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/LWDJD/ipfar-sdk/pow"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "compute":
		runCompute(os.Args[2:])
	case "verify":
		runVerify(os.Args[2:])
	case "bench":
		runBench(os.Args[2:])
	case "test":
		runTest(os.Args[2:])
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `ipfar-pow — IPFAR Proof-of-Work CLI

Usage:
  ipfar-pow compute --root-cid <cid> --data-txid <txid> [--workers 10] [--timeout 300] [--difficulty 2]
  ipfar-pow verify  --root-cid <cid> --data-txid <txid> --salt <salt> [--difficulty 2]
  ipfar-pow bench   [--workers 4] [--duration 30]
  ipfar-pow test    [--workers 10]
`)
}

// =============================================================================
// compute
// =============================================================================

func runCompute(args []string) {
	fs := flag.NewFlagSet("compute", flag.ExitOnError)
	rootCID := fs.String("root-cid", "", "Root CID of the data")
	dataTXID := fs.String("data-txid", "", "Arweave transaction ID of the data")
	workers := fs.Int("workers", 10, "Number of parallel workers")
	timeout := fs.Int("timeout", 300, "Timeout in seconds")
	difficulty := fs.Int("difficulty", 2, "PoW difficulty (leading zero bytes)")

	fs.Parse(args)

	if *rootCID == "" || *dataTXID == "" {
		fmt.Fprintln(os.Stderr, "error: --root-cid and --data-txid are required")
		os.Exit(1)
	}
	if *difficulty != 2 {
		fmt.Fprintln(os.Stderr, "error: only difficulty 2 is currently supported")
		os.Exit(1)
	}
	if *workers <= 0 {
		*workers = pow.DefaultWorkers()
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeout)*time.Second)
	defer cancel()

	startTime := time.Now()
	var totalAttempts uint64

	salt, err := pow.ComputePoW(ctx, *rootCID, *dataTXID, *workers, func(info pow.ProgressInfo) {
		totalAttempts = info.Attempts
		elapsed := time.Since(startTime).Seconds()
		speed := float64(0)
		if elapsed > 0 {
			speed = float64(info.Attempts) / elapsed
		}
		fmt.Fprintf(os.Stderr, "\rprogress: attempts=%s speed=%s elapsed=%.1fs",
			pow.FormatNumber(info.Attempts), pow.FormatSpeed(speed), elapsed)
	})
	// Clean up progress line.
	fmt.Fprintln(os.Stderr)

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: compute failed: %v\n", err)
		os.Exit(1)
	}

	elapsed := time.Since(startTime).Seconds()
	// Output result to stdout (machine-parseable).
	fmt.Printf("SALT=%s ATTEMPTS=%d TIME=%.1f\n", salt, totalAttempts, elapsed)
}

// =============================================================================
// verify
// =============================================================================

func runVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	rootCID := fs.String("root-cid", "", "Root CID of the data")
	dataTXID := fs.String("data-txid", "", "Arweave transaction ID of the data")
	saltStr := fs.String("salt", "", "Salt to verify")
	difficulty := fs.Int("difficulty", 2, "PoW difficulty (leading zero bytes)")

	fs.Parse(args)

	if *rootCID == "" || *dataTXID == "" || *saltStr == "" {
		fmt.Fprintln(os.Stderr, "error: --root-cid, --data-txid, and --salt are required")
		os.Exit(1)
	}
	if *difficulty < 1 || *difficulty > 32 {
		fmt.Fprintln(os.Stderr, "error: difficulty must be between 1 and 32")
		os.Exit(1)
	}

	// Parse salt.
	salt, err := strconv.ParseUint(*saltStr, 10, 64)
	if err != nil {
		fmt.Println("VALID=false")
		os.Exit(0)
	}

	// Compute Argon2id.
	password := []byte(*rootCID + *dataTXID)
	saltBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(saltBytes, salt)

	hash := argon2.IDKey(password, saltBytes, 1, 20*1024, 1, 32)

	if hasLeadingZeroBytes(hash, *difficulty) {
		fmt.Println("VALID=true")
	} else {
		fmt.Println("VALID=false")
	}
}

// =============================================================================
// bench
// =============================================================================

func runBench(args []string) {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	workers := fs.Int("workers", 4, "Number of parallel workers")
	durationSec := fs.Int("duration", 30, "Benchmark duration in seconds")

	fs.Parse(args)

	if *workers <= 0 {
		*workers = pow.DefaultWorkers()
	}

	fmt.Fprintf(os.Stderr, "Benchmarking with %d workers for %d seconds...\n", *workers, *durationSec)

	rootCID := "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
	dataTXID := "bench-txid"

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*durationSec)*time.Second)
	defer cancel()

	var totalAttempts uint64
	startTime := time.Now()

	_, err := pow.ComputePoW(ctx, rootCID, dataTXID, *workers, func(info pow.ProgressInfo) {
		totalAttempts = info.Attempts
		elapsed := time.Since(startTime).Seconds()
		speed := float64(0)
		if elapsed > 0 {
			speed = float64(info.Attempts) / elapsed
		}
		fmt.Fprintf(os.Stderr, "\rprogress: attempts=%s speed=%s elapsed=%.1fs",
			pow.FormatNumber(info.Attempts), pow.FormatSpeed(speed), elapsed)
	})
	fmt.Fprintln(os.Stderr)

	elapsed := time.Since(startTime).Seconds()
	if err != nil && err != pow.ErrPoWCancelled {
		fmt.Fprintf(os.Stderr, "warning: benchmark ended with error: %v\n", err)
	}

	throughput := float64(0)
	if elapsed > 0 {
		throughput = float64(totalAttempts) / elapsed
	}

	fmt.Printf("THROUGHPUT=%.0f WORKERS=%d\n", throughput, *workers)
}

// =============================================================================
// test
// =============================================================================

func runTest(args []string) {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	workers := fs.Int("workers", 10, "Number of parallel workers")
	only := fs.Int("only", 0, "Run only a specific test number (0 = all)")

	fs.Parse(args)

	if *workers <= 0 {
		*workers = pow.DefaultWorkers()
	}

	rootCID := "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"

	allPassed := true
	passed := 0
	failed := 0

	report := func(name string, err error) {
		if err != nil {
			fmt.Fprintf(os.Stderr, "  FAIL: %s — %v\n", name, err)
			allPassed = false
			failed++
		} else {
			fmt.Fprintf(os.Stderr, "  PASS: %s\n", name)
			passed++
		}
	}

	// ---------------------------------------------------------------
	// Test 1: difficulty-2 PoW computation (validates salt format)
	// ---------------------------------------------------------------
	if *only == 0 || *only == 1 {
		fmt.Fprintln(os.Stderr, "--- Test 1: PoW computation (difficulty 2) ---")
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
		defer cancel()

		salt, err := pow.ComputePoW(ctx, rootCID, "test-txid-1", *workers, nil)
		if err != nil {
			report("PoW compute (difficulty 2)", err)
		} else if salt == "" {
			report("PoW compute (difficulty 2)", fmt.Errorf("empty salt"))
		} else {
			// Validate salt is a decimal string.
			_, parseErr := strconv.ParseUint(salt, 10, 64)
			if parseErr != nil {
				report("PoW compute (difficulty 2)", fmt.Errorf("salt %q is not a valid uint64: %v", salt, parseErr))
			} else {
				// Also verify the salt actually works.
				saltUint, _ := strconv.ParseUint(salt, 10, 64)
				saltBytes := make([]byte, 8)
				binary.LittleEndian.PutUint64(saltBytes, saltUint)
				hash := argon2.IDKey([]byte(rootCID+"test-txid-1"), saltBytes, 1, 20*1024, 1, 32)
				if !hasLeadingZeroBytes(hash, 2) {
					report("PoW compute (difficulty 2)", fmt.Errorf("computed salt does not pass verification"))
				} else {
					report("PoW compute (difficulty 2)", nil)
				}
			}
		}
	}

	// ---------------------------------------------------------------
	// Test 2: progress callback test
	// ---------------------------------------------------------------
	if *only == 0 || *only == 2 {
		fmt.Fprintln(os.Stderr, "--- Test 2: progress callback ---")
		// No timeout — the computation must eventually find a result
		// (finite search space for difficulty 2). The user can Ctrl+C
		// if it takes too long.
		var maxAttempts uint64
		salt, err := pow.ComputePoW(context.Background(), rootCID, "test-txid-2", *workers, func(info pow.ProgressInfo) {
			if info.Attempts > maxAttempts {
				maxAttempts = info.Attempts
			}
		})
		if err != nil {
			report("progress callback", err)
		} else if salt == "" {
			report("progress callback", fmt.Errorf("empty salt"))
		} else if maxAttempts == 0 {
			report("progress callback", fmt.Errorf("progress callback reported 0 attempts"))
		} else {
			report("progress callback", nil)
		}
	}

	// ---------------------------------------------------------------
	// Test 3: cancellation test
	// ---------------------------------------------------------------
	if *only == 0 || *only == 3 {
		fmt.Fprintln(os.Stderr, "--- Test 3: cancellation ---")
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // immediately cancel

		_, err := pow.ComputePoW(ctx, rootCID, "test-txid-3", 4, nil)
		if err != pow.ErrPoWCancelled {
			report("cancellation", fmt.Errorf("expected ErrPoWCancelled, got %v", err))
		} else {
			report("cancellation", nil)
		}
	}

	// ---------------------------------------------------------------
	// Test 4: multiple workers test
	// ---------------------------------------------------------------
	if *only == 0 || *only == 4 {
		fmt.Fprintln(os.Stderr, "--- Test 4: multiple workers ---")
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
		defer cancel()

		salt, err := pow.ComputePoW(ctx, rootCID, "test-txid-4", *workers, nil)
		if err != nil {
			report("multiple workers", err)
		} else if salt == "" {
			report("multiple workers", fmt.Errorf("empty salt"))
		} else {
			_, parseErr := strconv.ParseUint(salt, 10, 64)
			if parseErr != nil {
				report("multiple workers", fmt.Errorf("salt %q is not a valid uint64: %v", salt, parseErr))
			} else {
				report("multiple workers", nil)
			}
		}
	}

	// ---------------------------------------------------------------
	// Test 5: cache test
	// ---------------------------------------------------------------
	if *only == 0 || *only == 5 {
		fmt.Fprintln(os.Stderr, "--- Test 5: cache ---")
		cachePath := filepath.Join(os.TempDir(), "ipfar-pow-test-cache.pow.json")
		cacheRootCID := rootCID
		cacheDataTXID := "test-cache-txid"
		cacheSalt := "12345"
		var cacheErr error

		// Clean up before and after.
		os.Remove(cachePath)
		defer os.Remove(cachePath)

		// Initially nothing cached.
		_, ok := pow.LoadPoWCache(cachePath, cacheRootCID, cacheDataTXID)
		if ok {
			cacheErr = fmt.Errorf("expected cache miss before save")
		}

		// Save cache.
		if cacheErr == nil {
			if err := pow.SavePoWCache(cachePath, cacheRootCID, cacheDataTXID, cacheSalt); err != nil {
				cacheErr = fmt.Errorf("SavePoWCache failed: %v", err)
			}
		}

		// Load cache.
		if cacheErr == nil {
			loaded, ok := pow.LoadPoWCache(cachePath, cacheRootCID, cacheDataTXID)
			if !ok {
				cacheErr = fmt.Errorf("expected cache hit after save")
			} else if loaded != cacheSalt {
				cacheErr = fmt.Errorf("expected salt %q, got %q", cacheSalt, loaded)
			}
		}

		// Mismatch rootCID.
		if cacheErr == nil {
			if _, ok := pow.LoadPoWCache(cachePath, "different-root-cid", cacheDataTXID); ok {
				cacheErr = fmt.Errorf("expected cache miss for different rootCID")
			}
		}

		// Mismatch dataTXID.
		if cacheErr == nil {
			if _, ok := pow.LoadPoWCache(cachePath, cacheRootCID, "different-data-txid"); ok {
				cacheErr = fmt.Errorf("expected cache miss for different dataTXID")
			}
		}

		// Non-existent file.
		if cacheErr == nil {
			if _, ok := pow.LoadPoWCache("/nonexistent/path.pow.json", cacheRootCID, cacheDataTXID); ok {
				cacheErr = fmt.Errorf("expected cache miss for non-existent file")
			}
		}

		report("cache", cacheErr)
	}

	// ---------------------------------------------------------------
	// Test 6: boundary conditions
	// ---------------------------------------------------------------
	if *only == 0 || *only == 6 {
		fmt.Fprintln(os.Stderr, "--- Test 6: boundary conditions ---")
		// hasLeadingZeroBytes tests.
		tests := []struct {
			data     []byte
			n        int
			expected bool
		}{
			{[]byte{0, 0, 1, 2}, 2, true},
			{[]byte{0, 0, 0, 0}, 4, true},
			{[]byte{0, 1, 0, 0}, 2, false},
			{[]byte{1, 0, 0, 0}, 1, false},
			{[]byte{0, 0}, 3, false},
			{[]byte{}, 1, false},
		}
		allBoundaryPassed := true
		for _, tt := range tests {
			if hasLeadingZeroBytes(tt.data, tt.n) != tt.expected {
				fmt.Fprintf(os.Stderr, "  boundary: hasLeadingZeroBytes(%v, %d) != %v\n", tt.data, tt.n, tt.expected)
				allBoundaryPassed = false
			}
		}

		// NeedsPoW tests.
		if pow.NeedsPoW(0) != true {
			fmt.Fprintf(os.Stderr, "  boundary: NeedsPoW(0) != true\n")
			allBoundaryPassed = false
		}
		if pow.NeedsPoW(100*1024*1024) != false {
			fmt.Fprintf(os.Stderr, "  boundary: NeedsPoW(100MiB) != false\n")
			allBoundaryPassed = false
		}
		if pow.NeedsPoW(100*1024*1024-1) != true {
			fmt.Fprintf(os.Stderr, "  boundary: NeedsPoW(100MiB-1) != true\n")
			allBoundaryPassed = false
		}

		// DefaultWorkers sanity.
		n := pow.DefaultWorkers()
		if n < 1 || n > 10 {
			fmt.Fprintf(os.Stderr, "  boundary: DefaultWorkers()=%d out of range [1,10]\n", n)
			allBoundaryPassed = false
		}

		if allBoundaryPassed {
			report("boundary conditions", nil)
		} else {
			report("boundary conditions", fmt.Errorf("one or more boundary checks failed"))
		}
	}

	// ---------------------------------------------------------------
	// Summary
	// ---------------------------------------------------------------
	fmt.Fprintln(os.Stderr, "========================================")
	fmt.Fprintf(os.Stderr, "Results: %d passed, %d failed\n", passed, failed)
	if allPassed {
		fmt.Println("ALL TESTS PASSED")
	} else {
		fmt.Println("SOME TESTS FAILED")
		os.Exit(1)
	}
}

// =============================================================================
// helpers
// =============================================================================

// hasLeadingZeroBytes checks whether the first n bytes of data are all zero.
func hasLeadingZeroBytes(data []byte, n int) bool {
	if len(data) < n {
		return false
	}
	for i := 0; i < n; i++ {
		if data[i] != 0 {
			return false
		}
	}
	return true
}
