package ipfar

import (
	"runtime"

	"github.com/LWDJD/ipfar-sdk/cache"
)

// Config holds the configuration for the IPFAR SDK.
// Use DefaultConfig() to get a sensible default.
type Config struct {
	// GatewayURLs are the Arweave gateway URLs to use.
	// The first is the primary; the rest are fallbacks.
	// Default: ["https://arweave.net", "https://ar-io.dev"]
	GatewayURLs []string

	// PoWWorkers is the number of parallel PoW workers.
	// 0 means use the default (runtime.NumCPU).
	PoWWorkers int

	// VerifyPoW enables PoW verification during Verify operations.
	VerifyPoW bool

	// VerifyIndex enables CAR index verification during Verify operations.
	VerifyIndex bool

	// VerifyReferenceChain enables reference chain verification.
	VerifyReferenceChain bool

	// VerifyIntegrity enables full data integrity verification.
	VerifyIntegrity bool

	// Cache is the cache implementation to use.
	// nil means no caching.
	Cache cache.Cache
}

// DefaultConfig returns a default configuration suitable for most use cases.
func DefaultConfig() *Config {
	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 4
	}

	return &Config{
		GatewayURLs: []string{
			"https://arweave.net",
			"https://ar-io.dev",
		},
		PoWWorkers: workers,
		VerifyPoW:             true,
		VerifyIndex:           true,
		VerifyReferenceChain:  true,
		VerifyIntegrity:       true,
		Cache:                 nil, // no caching by default
	}
}
