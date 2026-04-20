package arweave

import (
	"fmt"
	"testing"
)

func TestBlockParser(t *testing.T) {
	t.Run("FetchBlockByHeight", func(t *testing.T) {
		block, err := FetchBlockByHeight("https://arweave.net", 100)
		if err != nil {
			t.Fatalf("Failed to fetch block by height: %v", err)
		}

		if block.Height != 100 {
			t.Errorf("Expected height 100, got %d", block.Height)
		}

		if block.IndepHash == "" {
			t.Error("Expected non-empty indep_hash")
		}

		fmt.Printf("Block %d: %s\n", block.Height, block.IndepHash)
		fmt.Printf("  Transactions: %d\n", len(block.Txs))
		fmt.Printf("  Timestamp: %d\n", block.Timestamp)
	})

	t.Run("FetchCurrentBlock", func(t *testing.T) {
		block, err := FetchCurrentBlock("https://arweave.net")
		if err != nil {
			t.Fatalf("Failed to fetch current block: %v", err)
		}

		if block.Height <= 0 {
			t.Errorf("Expected positive height, got %d", block.Height)
		}

		fmt.Printf("Current block height: %d\n", block.Height)
		fmt.Printf("  Indep hash: %s\n", block.IndepHash)
	})

	t.Run("LightVerification", func(t *testing.T) {
		result, err := VerifyBlockLight("https://arweave.net", 100)
		if err != nil {
			t.Fatalf("Failed to verify block light: %v", err)
		}

		fmt.Printf("Light verification result:\n")
		fmt.Printf("  Height: %d\n", result.Height)
		fmt.Printf("  Valid: %v\n", result.IsValid)
		fmt.Printf("  Type: %s\n", result.VerificationType)
		if len(result.Errors) > 0 {
			fmt.Printf("  Errors: %v\n", result.Errors)
		}

		if !result.IsValid {
			t.Errorf("Expected block to be valid, but got errors: %v", result.Errors)
		}
	})

	t.Run("FullVerification", func(t *testing.T) {
		result, err := VerifyBlockFull("https://arweave.net", 100)
		if err != nil {
			t.Fatalf("Failed to verify block full: %v", err)
		}

		fmt.Printf("Full verification result:\n")
		fmt.Printf("  Height: %d\n", result.Height)
		fmt.Printf("  Valid: %v\n", result.IsValid)
		fmt.Printf("  Type: %s\n", result.VerificationType)
		if len(result.Errors) > 0 {
			fmt.Printf("  Errors: %v\n", result.Errors)
		}
	})

	t.Run("BlockParserFromURL", func(t *testing.T) {
		url := "https://arweave.net/block/height/100"
		parser := NewBlockParserFromURL(url)

		err := parser.ParseHeader()
		if err != nil {
			t.Fatalf("Failed to parse header: %v", err)
		}

		header, err := parser.GetHeader()
		if err != nil {
			t.Fatalf("Failed to get header: %v", err)
		}

		if header.Height != 100 {
			t.Errorf("Expected height 100, got %d", header.Height)
		}

		fmt.Printf("Parsed header: height=%d, indep_hash=%s\n", header.Height, header.IndepHash)
	})

	t.Run("BlockParserFullFromURL", func(t *testing.T) {
		url := "https://arweave.net/block/height/100"
		parser := NewBlockParserFromURL(url)

		err := parser.ParseFull()
		if err != nil {
			t.Fatalf("Failed to parse full block: %v", err)
		}

		block, err := parser.GetBlock()
		if err != nil {
			t.Fatalf("Failed to get block: %v", err)
		}

		if block.Height != 100 {
			t.Errorf("Expected height 100, got %d", block.Height)
		}

		txs, err := parser.GetTransactionIDs()
		if err != nil {
			t.Fatalf("Failed to get transaction IDs: %v", err)
		}

		fmt.Printf("Block %d has %d transactions\n", block.Height, len(txs))
		if len(txs) > 0 {
			fmt.Printf("  First tx: %s\n", txs[0])
		}
	})

	t.Run("GetBlockInfo", func(t *testing.T) {
		block, err := FetchBlockByHeight("https://arweave.net", 100)
		if err != nil {
			t.Fatalf("Failed to fetch block: %v", err)
		}

		parser := &BlockParser{
			block: block,
			header: &BlockHeader{
				Height:        block.Height,
				Hash:          block.Hash,
				IndepHash:     block.IndepHash,
				PreviousBlock: block.PreviousBlock,
				Timestamp:     block.Timestamp,
				TxRoot:        block.TxRoot,
				Nonce:         block.Nonce,
				Diff:          block.Diff.String(),
			},
		}

		txCount, err := parser.GetTransactionCount()
		if err != nil {
			t.Fatalf("Failed to get transaction count: %v", err)
		}
		fmt.Printf("Transaction count: %d\n", txCount)

		rewardAddr, err := parser.GetRewardAddr()
		if err != nil {
			t.Fatalf("Failed to get reward address: %v", err)
		}
		fmt.Printf("Reward address: %s\n", rewardAddr)

		weaveSize, err := parser.GetWeaveSize()
		if err != nil {
			t.Fatalf("Failed to get weave size: %v", err)
		}
		fmt.Printf("Weave size: %d bytes\n", weaveSize)

		blockSize, err := parser.GetBlockSize()
		if err != nil {
			t.Fatalf("Failed to get block size: %v", err)
		}
		fmt.Printf("Block size: %d bytes\n", blockSize)
	})

	t.Run("MerkleRootCalculation", func(t *testing.T) {
		txs := []string{"tx1", "tx2", "tx3"}
		root := calculateMerkleRoot(txs)
		if root == "" {
			t.Error("Expected non-empty merkle root")
		}
		fmt.Printf("Merkle root for 3 txs: %s\n", root)

		singleTx := []string{"tx1"}
		root = calculateMerkleRoot(singleTx)
		if root == "" {
			t.Error("Expected non-empty merkle root for single tx")
		}
		fmt.Printf("Merkle root for 1 tx: %s\n", root)

		emptyTxs := []string{}
		root = calculateMerkleRoot(emptyTxs)
		if root != "" {
			t.Error("Expected empty merkle root for empty txs")
		}
	})

	t.Run("FetchSingleTransactionTags", func(t *testing.T) {
		txID := "7BoxcxiJIjTwUp3JXp0xRJQXf6hZtyJj1kjGNiEl5A8"
		tags, err := FetchTransactionTags("https://arweave.net", txID)
		if err != nil {
			t.Fatalf("Failed to fetch transaction tags: %v", err)
		}

		fmt.Printf("Transaction %s tags:\n", txID)
		for i, tag := range tags {
			fmt.Printf("  [%d] %s: %s\n", i, tag.Name, tag.Value)
		}
	})

	t.Run("FetchBlockTransactionTags", func(t *testing.T) {
		result, err := FetchBlockTransactionTags("https://arweave.net", 100)
		if err != nil {
			t.Fatalf("Failed to fetch block transaction tags: %v", err)
		}

		fmt.Printf("Block 100 transaction tags:\n")
		for txID, tags := range result {
			fmt.Printf("  TX: %s\n", txID)
			for i, tag := range tags {
				fmt.Printf("    [%d] %s: %s\n", i, tag.Name, tag.Value)
			}
		}
	})

	t.Run("GetBlockTransactionInfo", func(t *testing.T) {
		txCount, err := GetBlockTransactionCount("https://arweave.net", 100)
		if err != nil {
			t.Fatalf("Failed to get transaction count: %v", err)
		}
		fmt.Printf("Block 100 transaction count: %d\n", txCount)

		txIDs, err := GetBlockTransactionIDs("https://arweave.net", 100)
		if err != nil {
			t.Fatalf("Failed to get transaction IDs: %v", err)
		}
		fmt.Printf("Block 100 transaction IDs: %v\n", txIDs)
	})

	t.Run("FetchSpecificTransactionTags", func(t *testing.T) {
		txIDs := []string{"7BoxcxiJIjTwUp3JXp0xRJQXf6hZtyJj1kjGNiEl5A8"}
		result, err := FetchBlockTransactionTagsLight("https://arweave.net", txIDs)
		if err != nil {
			t.Fatalf("Failed to fetch specific transaction tags: %v", err)
		}

		for txID, tags := range result {
			fmt.Printf("Transaction %s has %d tags:\n", txID, len(tags))
			for i, tag := range tags {
				fmt.Printf("  [%d] %s: %s\n", i, tag.Name, tag.Value)
			}
		}
	})

	t.Run("FetchTransactionTagsWithContent", func(t *testing.T) {
		txID := "gdXUJuj9EZm99TmeES7zRHCJtnJoP3XgYo_7KJNV8Vw"
		tags, err := FetchTransactionTags("https://arweave.net", txID)
		if err != nil {
			t.Fatalf("Failed to fetch transaction tags: %v", err)
		}

		fmt.Printf("Transaction %s tags (%d total):\n", txID, len(tags))
		for i, tag := range tags {
			fmt.Printf("  [%d] Name: %s, Value: %s\n", i, tag.Name, tag.Value)
		}

		if len(tags) == 0 {
			t.Logf("Warning: Transaction has no tags")
		}
	})

	t.Run("FetchBundleTransactionTags", func(t *testing.T) {
		txID := "jXN3mTRx5oLuOkfbGxy6DTqw1CS_X25cEJ-ASyrE8is"
		tags, err := FetchTransactionTags("https://arweave.net", txID)
		if err != nil {
			t.Fatalf("Failed to fetch bundle transaction tags: %v", err)
		}

		fmt.Printf("Bundle transaction %s tags (%d total):\n", txID, len(tags))
		for i, tag := range tags {
			fmt.Printf("  [%d] Name: %s, Value: %s\n", i, tag.Name, tag.Value)
		}
	})
}
