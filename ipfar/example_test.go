package ipfar_test

import (
	"context"
	"fmt"
	"log"

	"github.com/LWDJD/ipfar-sdk/arweave"
	"github.com/LWDJD/ipfar-sdk/cache"
	"github.com/LWDJD/ipfar-sdk/ipfar"
)

// Example_upload demonstrates how to upload a file using the IPFAR SDK.
func Example_upload() {
	// Create a gateway client pointing to arweave.net.
	gw := arweave.NewGatewayClient("https://arweave.net")

	// Load an Arweave wallet from a JWK file.
	wallet, err := arweave.LoadWalletFromFile("wallet.json")
	if err != nil {
		log.Fatalf("Failed to load wallet: %v", err)
	}

	// Upload a file with default options.
	result, err := ipfar.Upload(context.Background(), gw, wallet, "example.txt", nil)
	if err != nil {
		fmt.Printf("Upload failed: %v\n", err)
		return
	}
	fmt.Printf("Uploaded: CID=%s, CAR=%s, Meta=%s\n",
		result.RootCID, result.DataTXID, result.MetaTXID)
}

// Example_verify demonstrates how to verify a file's on-chain integrity
// using its metadata transaction ID.
func Example_verify() {
	gw := arweave.NewGatewayClient("https://ar-io.dev")

	result, err := ipfar.Verify(context.Background(), gw, "bafkrei...", &ipfar.VerifyOptions{
		MetadataTXID: "metadata-txid-here",
	})
	if err != nil {
		fmt.Printf("Verify failed: %v\n", err)
		return
	}
	fmt.Printf("Valid: %v\n", result.Valid)
}

// Example_download demonstrates how to download a file by its Root CID.
func Example_download() {
	gw := arweave.NewGatewayClient("https://arweave.net")

	data, err := ipfar.Download(context.Background(), gw, "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")
	if err != nil {
		fmt.Printf("Download failed: %v\n", err)
		return
	}
	fmt.Printf("Downloaded %d bytes\n", len(data))
}

// Example_dedup demonstrates how to check for existing CAR data before uploading.
func Example_dedup() {
	gw := arweave.NewGatewayClient("https://arweave.net")

	txid, height, err := ipfar.FindExistingCAR(
		context.Background(),
		gw,
		"bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
		nil, // use default fallback gateways
	)
	if err != nil {
		fmt.Printf("Dedup query failed: %v\n", err)
		return
	}
	if txid != "" {
		fmt.Printf("Found existing CAR: tx=%s, height=%d\n", txid, height)
	} else {
		fmt.Println("No existing CAR found; fresh upload needed.")
	}
}

// ExampleConfig demonstrates how to configure the SDK with custom options
// and a cache.
func ExampleConfig() {
	// Start with sensible defaults.
	cfg := ipfar.DefaultConfig()

	// Override specific fields.
	cfg.GatewayURLs = []string{"https://ar-io.dev", "https://arweave.net"}
	cfg.PoWWorkers = 8
	cfg.VerifyPoW = true

	// Attach an in-memory cache (128 MiB).
	cfg.Cache = cache.NewMemoryCache(128 * 1024 * 1024)

	fmt.Printf("Gateways: %v\n", cfg.GatewayURLs)
	fmt.Printf("PoW workers: %d\n", cfg.PoWWorkers)
	fmt.Printf("Cache max size: %d\n", cfg.Cache.Stats().MaxSize)

	// Output:
	// Gateways: [https://ar-io.dev https://arweave.net]
	// PoW workers: 8
	// Cache max size: 134217728
}
