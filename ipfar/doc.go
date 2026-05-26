// Package ipfar provides a high-level API for the IPFS↔Arweave Bridge (IPFAR)
// protocol.  It handles the full lifecycle of IPFAR data:
//
// # Upload
//
// Upload a file: CAR v2 building → dedup → PoW → metadata → upload
//
// Usage:
//
//	result, err := ipfar.Upload(ctx, gateway, wallet, filePath, opts)
//
// # Download
//
// Download a file by Root CID: find metadata → download CAR → extract
//
// Usage:
//
//	data, err := ipfar.Download(ctx, gateway, rootCID)
//
// # Verify
//
// Verify on-chain data against the IPFAR V1 specification.
//
// Usage:
//
//	result, err := ipfar.Verify(ctx, gateway, rootCID, opts)
//
// # Dedup
//
// Check if data already exists on Arweave before uploading.
//
// Usage:
//
//	txid, height, err := ipfar.FindExistingCAR(ctx, gateway, rootCID, gateways)
//
// # Configuration
//
// The SDK can be configured via the Config struct:
//
//	cfg := ipfar.DefaultConfig()
//	cfg.Cache = cache.NewMemoryCache(128 * 1024 * 1024) // 128 MiB
//
// See https://github.com/LWDJD/ipfar-sdk for more information.
package ipfar
