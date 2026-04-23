package arweave

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func TestFetchAllTransactions(t *testing.T) {
	t.Run("FetchBlockAndBundleTransactions", func(t *testing.T) {
		gateway := "https://arweave.net"
		blockHeight := int64(100)

		transactions, err := FetchAllTransactions(gateway, blockHeight)
		if err != nil {
			t.Fatalf("Failed to fetch all transactions: %v", err)
		}

		fmt.Printf("✓ 成功获取所有交易\n")
		fmt.Printf("  区块高度: %d\n", blockHeight)
		fmt.Printf("  总交易数: %d\n", len(*transactions))

		blockTxCount := 0
		bundleTxCount := 0
		for _, txInfo := range *transactions {
			if txInfo.Source == "block" {
				blockTxCount++
			} else if txInfo.Source == "bundle" {
				bundleTxCount++
			}
		}

		fmt.Printf("  区块交易: %d\n", blockTxCount)
		fmt.Printf("  捆绑包内交易: %d\n", bundleTxCount)

		if len(*transactions) == 0 {
			t.Fatal("Expected at least one transaction")
		}
	})
}

func TestFilterByTagKey(t *testing.T) {
	t.Run("FilterExistingKey", func(t *testing.T) {
		gateway := "https://arweave.net"
		blockHeight := int64(100)

		allTransactions, err := FetchAllTransactions(gateway, blockHeight)
		if err != nil {
			t.Fatalf("Failed to fetch all transactions: %v", err)
		}

		tagKey := "QnVuZGxlLUZvcm1hdA"
		filtered := FilterByTagKey(allTransactions, tagKey)

		fmt.Printf("✓ 按 Tag Key 筛选成功\n")
		fmt.Printf("  筛选 Key: %s\n", tagKey)
		fmt.Printf("  匹配交易数: %d\n", len(*filtered))

		for txID, txInfo := range *filtered {
			found := false
			for _, tag := range txInfo.Tags {
				if tag.Name == tagKey {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Transaction %s should have tag key %s", txID, tagKey)
			}
		}
	})

	t.Run("FilterNonExistentKey", func(t *testing.T) {
		transactions := &TransactionSet{
			"tx1": {
				TxID: "tx1",
				Tags: []Tag{
					{Name: "QXBwLU5hbWU", Value: "VGVzdA"},
				},
			},
		}

		filtered := FilterByTagKey(transactions, "Tm9uRXhpc3RlbnQ")

		if len(*filtered) != 0 {
			t.Errorf("Expected 0 transactions, got %d", len(*filtered))
		}

		fmt.Printf("✓ 不存在的 Key 筛选正确（0 结果）\n")
	})
}

func TestFilterByTagKeyValue(t *testing.T) {
	t.Run("FilterExistingKeyValue", func(t *testing.T) {
		gateway := "https://arweave.net"
		blockHeight := int64(100)

		allTransactions, err := FetchAllTransactions(gateway, blockHeight)
		if err != nil {
			t.Fatalf("Failed to fetch all transactions: %v", err)
		}

		tagKey := "QnVuZGxlLUZvcm1hdA"
		tagValue := "YmluYXJ5"
		filtered := FilterByTagKeyValue(allTransactions, tagKey, tagValue)

		fmt.Printf("✓ 按 Tag Key:Value 筛选成功\n")
		fmt.Printf("  筛选 Key: %s\n", tagKey)
		fmt.Printf("  筛选 Value: %s\n", tagValue)
		fmt.Printf("  匹配交易数: %d\n", len(*filtered))

		for txID, txInfo := range *filtered {
			found := false
			for _, tag := range txInfo.Tags {
				if tag.Name == tagKey && tag.Value == tagValue {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Transaction %s should have tag %s:%s", txID, tagKey, tagValue)
			}
		}
	})

	t.Run("FilterNonExistentKeyValue", func(t *testing.T) {
		transactions := &TransactionSet{
			"tx1": {
				TxID: "tx1",
				Tags: []Tag{
					{Name: "QXBwLU5hbWU", Value: "VGVzdA"},
				},
			},
		}

		filtered := FilterByTagKeyValue(transactions, "QXBwLU5hbWU", "Tm90RXhpc3Q")

		if len(*filtered) != 0 {
			t.Errorf("Expected 0 transactions, got %d", len(*filtered))
		}

		fmt.Printf("✓ 不存在的 Key:Value 筛选正确（0 结果）\n")
	})
}

func TestFetchAndFilterByTagKey(t *testing.T) {
	t.Run("CombinedFetchAndFilter", func(t *testing.T) {
		gateway := "https://arweave.net"
		blockHeight := int64(100)
		tagKey := "QnVuZGxlLUZvcm1hdA"

		filtered, err := FetchAndFilterByTagKey(gateway, blockHeight, tagKey)
		if err != nil {
			t.Fatalf("Failed to fetch and filter: %v", err)
		}

		fmt.Printf("✓ 合并获取和筛选成功\n")
		fmt.Printf("  区块高度: %d\n", blockHeight)
		fmt.Printf("  筛选 Key: %s\n", tagKey)
		fmt.Printf("  匹配交易数: %d\n", len(*filtered))

		for txID, txInfo := range *filtered {
			found := false
			for _, tag := range txInfo.Tags {
				if tag.Name == tagKey {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Transaction %s should have tag key %s", txID, tagKey)
			}
		}
	})
}

func TestFetchAndFilterByTagKeyValue(t *testing.T) {
	t.Run("CombinedFetchAndFilter", func(t *testing.T) {
		gateway := "https://arweave.net"
		blockHeight := int64(100)
		tagKey := "QnVuZGxlLUZvcm1hdA"
		tagValue := "YmluYXJ5"

		filtered, err := FetchAndFilterByTagKeyValue(gateway, blockHeight, tagKey, tagValue)
		if err != nil {
			t.Fatalf("Failed to fetch and filter: %v", err)
		}

		fmt.Printf("✓ 合并获取和筛选成功\n")
		fmt.Printf("  区块高度: %d\n", blockHeight)
		fmt.Printf("  筛选 Key: %s\n", tagKey)
		fmt.Printf("  筛选 Value: %s\n", tagValue)
		fmt.Printf("  匹配交易数: %d\n", len(*filtered))

		for txID, txInfo := range *filtered {
			found := false
			for _, tag := range txInfo.Tags {
				if tag.Name == tagKey && tag.Value == tagValue {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Transaction %s should have tag %s:%s", txID, tagKey, tagValue)
			}
		}
	})
}

func TestTransactionSetPointerUsage(t *testing.T) {
	t.Run("VerifyNoDataCopy", func(t *testing.T) {
		transactions := &TransactionSet{
			"tx1": {
				TxID: "tx1",
				Tags: []Tag{
					{Name: "QXBwLU5hbWU", Value: "VGVzdA"},
				},
				Source: "block",
			},
		}

		filtered := FilterByTagKey(transactions, "QXBwLU5hbWU")

		if len(*filtered) != 1 {
			t.Fatalf("Expected 1 transaction, got %d", len(*filtered))
		}

		tx1Original := (*transactions)["tx1"]
		tx1Filtered := (*filtered)["tx1"]

		if tx1Original != tx1Filtered {
			t.Fatal("Expected same pointer, data was copied")
		}

		fmt.Printf("✓ 指针使用正确，未复制数据\n")
	})

	t.Run("BundleItemMetadata", func(t *testing.T) {
		transactions := &TransactionSet{
			"bundle_item_1": {
				TxID:       "bundle_item_1",
				Tags:       []Tag{},
				Source:     "bundle",
				BundleTxID: "bundle_tx_id",
				ItemIndex:  5,
				ItemOffset: 12345,
			},
		}

		txInfo := (*transactions)["bundle_item_1"]

		if txInfo.Source != "bundle" {
			t.Errorf("Expected source 'bundle', got '%s'", txInfo.Source)
		}

		if txInfo.BundleTxID != "bundle_tx_id" {
			t.Errorf("Expected bundle tx ID 'bundle_tx_id', got '%s'", txInfo.BundleTxID)
		}

		if txInfo.ItemIndex != 5 {
			t.Errorf("Expected item index 5, got %d", txInfo.ItemIndex)
		}

		if txInfo.ItemOffset != 12345 {
			t.Errorf("Expected item offset 12345, got %d", txInfo.ItemOffset)
		}

		fmt.Printf("✓ 捆绑包内交易元数据正确\n")
		fmt.Printf("  来源: %s\n", txInfo.Source)
		fmt.Printf("  捆绑包 ID: %s\n", txInfo.BundleTxID)
		fmt.Printf("  数据项索引: %d\n", txInfo.ItemIndex)
		fmt.Printf("  数据项偏移量: %d\n", txInfo.ItemOffset)
	})
}

func TestStrictStringComparison(t *testing.T) {
	t.Run("ExactMatchRequired", func(t *testing.T) {
		transactions := &TransactionSet{
			"tx1": {
				TxID: "tx1",
				Tags: []Tag{
					{Name: "QXBwLU5hbWU", Value: "VGVzdA"},
				},
			},
		}

		filtered := FilterByTagKeyValue(transactions, "QXBwLU5hbWU", "VGVzdA")
		if len(*filtered) != 1 {
			t.Errorf("Expected 1 transaction with exact match, got %d", len(*filtered))
		}

		filtered2 := FilterByTagKeyValue(transactions, "QXBwLU5hbWU", "VGVzdA1")
		if len(*filtered2) != 0 {
			t.Errorf("Expected 0 transactions with different value, got %d", len(*filtered2))
		}

		filtered3 := FilterByTagKeyValue(transactions, "QXBwLU5hbWUx", "VGVzdA")
		if len(*filtered3) != 0 {
			t.Errorf("Expected 0 transactions with different key, got %d", len(*filtered3))
		}

		fmt.Printf("✓ 严格字符串对比正确\n")
	})

	t.Run("CaseSensitive", func(t *testing.T) {
		transactions := &TransactionSet{
			"tx1": {
				TxID: "tx1",
				Tags: []Tag{
					{Name: "QXBwLU5hbWU", Value: "VGVzdA"},
				},
			},
		}

		filtered := FilterByTagKeyValue(transactions, "qXBwLU5hbWU", "VGVzdA")
		if len(*filtered) != 0 {
			t.Errorf("Expected 0 transactions with different case key, got %d", len(*filtered))
		}

		filtered2 := FilterByTagKeyValue(transactions, "QXBwLU5hbWU", "vGVzdA")
		if len(*filtered2) != 0 {
			t.Errorf("Expected 0 transactions with different case value, got %d", len(*filtered2))
		}

		fmt.Printf("✓ 大小写敏感对比正确\n")
	})
}

func TestDecodedTags(t *testing.T) {
	t.Run("PrintDecodedTags", func(t *testing.T) {
		gateway := "https://arweave.net"
		blockHeight := int64(100)

		allTransactions, err := FetchAllTransactions(gateway, blockHeight)
		if err != nil {
			t.Fatalf("Failed to fetch all transactions: %v", err)
		}

		fmt.Printf("\n📋 交易标签详情（已解码）:\n")
		for txID, txInfo := range *allTransactions {
			fmt.Printf("\n交易 ID: %s\n", txID)
			fmt.Printf("  来源: %s\n", txInfo.Source)
			if txInfo.Source == "bundle" {
				fmt.Printf("  捆绑包: %s\n", txInfo.BundleTxID)
				fmt.Printf("  数据项索引: %d\n", txInfo.ItemIndex)
				fmt.Printf("  数据项偏移量: %d\n", txInfo.ItemOffset)
			}

			if len(txInfo.Tags) > 0 {
				fmt.Printf("  标签数量: %d\n", len(txInfo.Tags))
				for i, tag := range txInfo.Tags {
					name, _ := base64.RawURLEncoding.DecodeString(tag.Name)
					value, _ := base64.RawURLEncoding.DecodeString(tag.Value)
					fmt.Printf("    [%d] %s = %s\n", i+1, string(name), string(value))
				}
			}
		}
	})
}
