package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/LWDJD/ipfar-sdk/arweave"
	"github.com/LWDJD/ipfar-sdk/ipfar"
)

func main() {
	var (
		gateway  = flag.String("gateway", "https://arweave.net", "Arweave gateway URL")
		rootCID  = flag.String("root-cid", "", "Root CID to verify")
		metaTXID = flag.String("meta-txid", "", "Metadata transaction ID to verify directly")
	)
	flag.Parse()

	if *rootCID == "" || *metaTXID == "" {
		fmt.Fprintf(os.Stderr, "Usage: verify-tool --root-cid <cid> --meta-txid <txid>\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	arw := arweave.NewGatewayClient(*gateway)

	result, err := ipfar.Verify(ctx, arw, *rootCID, &ipfar.VerifyOptions{
		GatewayURLs:  []string{"https://ar-io.dev"},
		MetadataTXID: *metaTXID,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Verify failed: %v\n", err)
		os.Exit(1)
	}

	if result.Valid {
		fmt.Println("✅ Verify: VALID")
		os.Exit(0)
	} else {
		fmt.Println("❌ Verify: INVALID")
		for _, e := range result.Errors {
			fmt.Printf("  - %s\n", e)
		}
		os.Exit(1)
	}
}
