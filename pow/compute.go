// Package pow provides IPFAR Proof-of-Work computation.
// It implements parallel Argon2id-based PoW search with caching,
// progress reporting, and cancellation support.
package pow

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
)

// =============================================================================
// Constants — must match ipfar-specs/V1/项目规划.md §2.1
// =============================================================================

const (
	// Algorithm is the PoW algorithm identifier.
	Algorithm = "argon2id-light-v1"

	argon2Memory  = 20 * 1024 // 20 MB (KB)
	argon2Time    = 1
	argon2Threads = 1
	argon2KeyLen  = 32

	// MinLeadingZeroBytes is the PoW difficulty: hash output must start
	// with at least this many zero bytes.
	MinLeadingZeroBytes = 2

	// PoWThreshold is the file size above which PoW is not required.
	PoWThreshold = 100 * 1024 * 1024

	// maxAttemptsPerWorker caps the number of attempts per worker goroutine
	// to prevent infinite loops in pathological cases.
	maxAttemptsPerWorker = 10_000_000
)

// =============================================================================
// Errors
// =============================================================================

var (
	ErrPoWCancelled   = errors.New("PoW computation cancelled")
	ErrPoWExhausted   = errors.New("PoW computation exceeded safety limit")
	ErrInvalidWorkers = errors.New("numWorkers must be >= 0")
)

// =============================================================================
// PoW Cache
// =============================================================================

// PoWCache is stored alongside the file as {filename}.pow.json.
type PoWCache struct {
	RootCID  string `json:"root_cid"`
	DataTXID string `json:"data_txid"`
	Salt     string `json:"salt"`
}

// LoadPoWCache reads a cache file and returns the salt if rootCID and
// dataTXID match. Returns ("", false) on any miss or error.
func LoadPoWCache(cachePath string, rootCID, dataTXID string) (string, bool) {
	data, err := os.ReadFile(cachePath)
	if err != nil {
		return "", false
	}
	var c PoWCache
	if err := json.Unmarshal(data, &c); err != nil {
		return "", false
	}
	if c.RootCID == rootCID && c.DataTXID == dataTXID {
		return c.Salt, true
	}
	return "", false
}

// SavePoWCache writes the PoW cache to disk.
func SavePoWCache(cachePath string, rootCID, dataTXID, salt string) error {
	c := PoWCache{
		RootCID:  rootCID,
		DataTXID: dataTXID,
		Salt:     salt,
	}
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(cachePath, data, 0644)
}

// =============================================================================
// Progress reporting
// =============================================================================

// ProgressInfo reports PoW computation progress.
type ProgressInfo struct {
	Attempts uint64 // Total attempts across all workers
	Found    bool   // Whether a valid salt has been found
	Salt     string // The valid salt (only set when Found is true)
}

// =============================================================================
// Public API
// =============================================================================

// DefaultWorkers returns the default number of parallel PoW workers.
// Caps at 4 to stay within reasonable memory limits (~80 MB for 4 workers
// at 20 MB per Argon2id invocation).
func DefaultWorkers() int {
	n := runtime.NumCPU()
	if n > 4 {
		n = 4
	}
	if n < 1 {
		n = 1
	}
	return n
}

// NeedsPoW returns true if the data size requires a PoW proof.
// Files >= 100 MiB are exempt from PoW.
func NeedsPoW(dataSize int64) bool {
	return dataSize < PoWThreshold
}

// ComputePoW computes the Proof of Work for the given rootCID + dataTXID
// combination. It runs a parallel random search across the specified number
// of workers.
//
// Parameters:
//   - ctx: context for cancellation
//   - rootCID: the root CID of the data
//   - dataTXID: the Arweave transaction ID of the data
//   - workers: number of parallel workers. If <= 0, DefaultWorkers() is used.
//   - progress: optional progress callback. Called periodically with current
//     attempt count. May be nil.
//
// Returns the salt as a decimal string that satisfies the difficulty
// requirement.
func ComputePoW(ctx context.Context, rootCID, dataTXID string, workers int, progress func(ProgressInfo)) (string, error) {
	if workers <= 0 {
		workers = DefaultWorkers()
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	password := []byte(rootCID + dataTXID)
	seedBase := time.Now().UnixNano()

	type result struct {
		salt uint64
		err  error
	}

	resultCh := make(chan result, 1)
	var found atomic.Bool
	var totalAttempts atomic.Uint64

	// Progress reporting goroutine.
	if progress != nil {
		go func() {
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					current := totalAttempts.Load()
					progress(ProgressInfo{
						Attempts: current,
						Found:    found.Load(),
					})
				}
			}
		}()
	}

	// Launch workers with independent RNGs.
	for w := 0; w < workers; w++ {
		go func(workerID int) {
			rng := rand.New(rand.NewSource(seedBase + int64(workerID)))
			var attempts uint64
			saltBytes := make([]byte, 8) // reused across iterations

			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				if found.Load() {
					return
				}

				salt := rng.Uint64()
				binary.LittleEndian.PutUint64(saltBytes, salt)
				hash := argon2.IDKey(password, saltBytes, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

				if hasLeadingZeroBytes(hash, MinLeadingZeroBytes) {
					if found.CompareAndSwap(false, true) {
						totalAttempts.Add(1)
						// Send result; defer cancel() at the top will clean up.
						// Don't call cancel() here — it creates a race where
						// the outer select can randomly pick ctx.Done() and
						// drop the result.
						select {
						case resultCh <- result{salt: salt}:
						default:
						}
					}
					return
				}

				totalAttempts.Add(1)
				attempts++

				if attempts > maxAttemptsPerWorker {
					if found.CompareAndSwap(false, true) {
						select {
						case resultCh <- result{err: ErrPoWExhausted}:
						default:
						}
					}
					return
				}
			}
		}(w)
	}

	select {
	case r := <-resultCh:
		if r.err != nil {
			return "", r.err
		}
		salt := strconv.FormatUint(r.salt, 10)

		if progress != nil {
			progress(ProgressInfo{
				Attempts: totalAttempts.Load(),
				Found:    true,
				Salt:     salt,
			})
		}

		return salt, nil
	case <-ctx.Done():
		return "", ErrPoWCancelled
	}
}

// =============================================================================
// Helpers
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

// FormatSpeed formats a hash-per-second rate for display.
func FormatSpeed(hps float64) string {
	switch {
	case hps >= 1_000_000:
		return fmt.Sprintf("%.1f M/s", hps/1_000_000)
	case hps >= 1000:
		return fmt.Sprintf("%.1f K/s", hps/1000)
	default:
		return fmt.Sprintf("%.0f h/s", hps)
	}
}

// FormatNumber formats a uint64 with comma separators for display.
func FormatNumber(n uint64) string {
	s := strconv.FormatUint(n, 10)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}
