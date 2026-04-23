package arweave

import (
	"fmt"
	"sync"
)

// TransactionInfo 交易信息，包含基础信息和标签
// 使用指针避免数据复制
type TransactionInfo struct {
	TxID       string // 交易 ID
	Tags       []Tag  // 交易标签（指向原始数据，不复制）
	Source     string // 交易来源："block" 或 "bundle"
	BundleTxID string // 如果来自捆绑包，记录捆绑包交易 ID
	ItemIndex  int    // 如果在捆绑包内，记录数据项索引
	ItemOffset int    // 如果在捆绑包内，记录数据项偏移量
}

// TransactionSet 交易集合，使用 map 避免重复
type TransactionSet map[string]*TransactionInfo

// FetchAllTransactions 轻量获取区块和捆绑包内所有交易信息和tags
// 返回指向 TransactionSet 的指针，避免数据复制
func FetchAllTransactions(gateway string, blockHeight int64) (*TransactionSet, error) {
	result := make(TransactionSet)
	var mu sync.Mutex

	gateways := []string{gateway}
	if gateway == "https://arweave.net" {
		gateways = DefaultGateways
	}

	var block *Block
	var fetchErr error
	var successGateway string

	for _, gw := range gateways {
		block, fetchErr = FetchBlockByHeight(gw, blockHeight)
		if fetchErr == nil {
			successGateway = gw
			break
		}
	}

	if block == nil {
		return nil, fmt.Errorf("failed to fetch block: %v", fetchErr)
	}

	errChan := make(chan error, len(block.Txs))

	for _, txID := range block.Txs {
		go func(id string) {
			tags, err := FetchTransactionTags(successGateway, id)
			if err != nil {
				errChan <- fmt.Errorf("tx %s: %v", id, err)
				return
			}

			mu.Lock()
			result[id] = &TransactionInfo{
				TxID:   id,
				Tags:   tags,
				Source: "block",
			}
			mu.Unlock()
			errChan <- nil
		}(txID)
	}

	for i := 0; i < len(block.Txs); i++ {
		<-errChan
	}

	for txID, txInfo := range result {
		isBundle := false
		for _, tag := range txInfo.Tags {
			if tag.Name == "QnVuZGxlLUZvcm1hdA" {
				isBundle = true
				break
			}
		}

		if isBundle {
			err := fetchBundleItems(successGateway, txID, &result, &mu)
			if err != nil {
				return &result, fmt.Errorf("failed to fetch bundle items for %s: %v", txID, err)
			}
		}
	}

	return &result, nil
}

func fetchBundleItems(gateway, bundleTxID string, result *TransactionSet, mu *sync.Mutex) error {
	parser, err := ParseBundleHeaderFromURL(fmt.Sprintf("%s/raw/%s", gateway, bundleTxID))
	if err != nil {
		return fmt.Errorf("failed to parse bundle header: %v", err)
	}

	index := parser.GetIndex()
	if index == nil {
		return fmt.Errorf("bundle index is nil")
	}

	errChan := make(chan error, index.ItemsNum)

	for i := 0; i < index.ItemsNum; i++ {
		go func(itemIdx int) {
			tags, err := parser.FetchItemTags(itemIdx)
			if err != nil {
				errChan <- fmt.Errorf("item %d: %v", itemIdx, err)
				return
			}

			meta := index.ItemsMeta[itemIdx]

			mu.Lock()
			(*result)[meta.Id] = &TransactionInfo{
				TxID:       meta.Id,
				Tags:       tags,
				Source:     "bundle",
				BundleTxID: bundleTxID,
				ItemIndex:  itemIdx,
				ItemOffset: meta.Offset,
			}
			mu.Unlock()
			errChan <- nil
		}(i)
	}

	var errs []string
	for i := 0; i < index.ItemsNum; i++ {
		if err := <-errChan; err != nil {
			errs = append(errs, err.Error())
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("some items failed: %v", errs)
	}

	return nil
}

// FilterByTagKey 从交易set中筛选包含指定tag Key的交易
// 使用严格字符串对比
func FilterByTagKey(transactions *TransactionSet, tagKey string) *TransactionSet {
	result := make(TransactionSet)

	for txID, txInfo := range *transactions {
		for _, tag := range txInfo.Tags {
			if tag.Name == tagKey {
				result[txID] = txInfo
				break
			}
		}
	}

	return &result
}

// FilterByTagKeyValue 从交易set中筛选包含指定tag Key:Value的交易
// 使用严格字符串对比
func FilterByTagKeyValue(transactions *TransactionSet, tagKey, tagValue string) *TransactionSet {
	result := make(TransactionSet)

	for txID, txInfo := range *transactions {
		for _, tag := range txInfo.Tags {
			if tag.Name == tagKey && tag.Value == tagValue {
				result[txID] = txInfo
				break
			}
		}
	}

	return &result
}

// FetchAndFilterByTagKey 合并功能1和2：获取所有交易并筛选包含指定tag Key的交易
func FetchAndFilterByTagKey(gateway string, blockHeight int64, tagKey string) (*TransactionSet, error) {
	allTransactions, err := FetchAllTransactions(gateway, blockHeight)
	if err != nil {
		return nil, err
	}

	return FilterByTagKey(allTransactions, tagKey), nil
}

// FetchAndFilterByTagKeyValue 合并功能1和3：获取所有交易并筛选包含指定tag Key:Value的交易
func FetchAndFilterByTagKeyValue(gateway string, blockHeight int64, tagKey, tagValue string) (*TransactionSet, error) {
	allTransactions, err := FetchAllTransactions(gateway, blockHeight)
	if err != nil {
		return nil, err
	}

	return FilterByTagKeyValue(allTransactions, tagKey, tagValue), nil
}
