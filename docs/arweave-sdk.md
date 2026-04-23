# Arweave 验证 SDK 文档

本文档描述了 Arweave 验证 SDK 的所有功能，包括区块解析、捆绑包处理、交易集合管理和轻量级验证。

## 目录

- [概述](#概述)
- [区块功能](#区块功能)
  - [数据结构](#区块数据结构)
  - [区块获取](#区块获取)
  - [区块验证](#区块验证)
  - [交易标签获取](#交易标签获取)
- [捆绑包功能](#捆绑包功能)
  - [数据结构](#捆绑包数据结构)
  - [捆绑包解析](#捆绑包解析)
  - [捆绑包验证](#捆绑包验证)
  - [轻量级标签获取](#轻量级标签获取)
- [交易集合功能](#交易集合功能)
  - [数据结构](#交易集合数据结构)
  - [获取所有交易](#获取所有交易)
  - [交易筛选](#交易筛选)
  - [合并功能](#合并功能)
- [轻量级验证](#轻量级验证)
  - [网络流量跟踪](#网络流量跟踪)
  - [HTTP Range 请求](#http-range-请求)
- [使用示例](#使用示例)

---

## 概述

Arweave 验证 SDK 提供以下核心能力：

- **区块解析和验证**：支持轻量级和全量验证
- **ANS-104 捆绑包处理**：支持解析、验证和轻量级标签获取
- **交易集合管理**：获取区块和捆绑包内所有交易，按标签筛选
- **轻量级操作**：使用 HTTP Range 请求最小化网络流量

---

## 区块功能

### 区块数据结构

#### Block
表示一个完整的 Arweave 区块。

| 字段 | 类型 | 说明 |
|------|------|------|
| Nonce | string | 随机数 |
| PreviousBlock | string | 前一个区块哈希 |
| Timestamp | int64 | 时间戳 |
| Height | int64 | 区块高度 |
| Hash | string | 区块哈希 |
| IndepHash | string | 独立哈希 |
| Txs | []string | 交易 ID 列表 |
| TxRoot | string | 交易根哈希 |
| RewardAddr | string | 奖励地址 |
| Tags | []Tag | 标签数组 |
| POA | *ProofOfAccess | 访问证明 |

#### BlockHeader
区块头部信息，用于轻量验证。

| 字段 | 类型 | 说明 |
|------|------|------|
| Height | int64 | 区块高度 |
| Hash | string | 区块哈希 |
| IndepHash | string | 独立哈希 |
| PreviousBlock | string | 前一个区块哈希 |
| Timestamp | int64 | 时间戳 |
| TxRoot | string | 交易根哈希 |
| Nonce | string | 随机数 |
| Diff | string | 难度 |

#### BlockVerificationResult
区块验证结果。

| 字段 | 类型 | 说明 |
|------|------|------|
| Height | int64 | 区块高度 |
| IndepHash | string | 区块独立哈希 |
| IsValid | bool | 是否有效 |
| VerificationType | string | 验证类型：light 或 full |
| Errors | []string | 验证错误列表 |

### 区块获取

#### FetchBlockByHeight
通过高度获取完整区块。

```go
func FetchBlockByHeight(gateway string, height int64) (*Block, error)
```

**参数：**
- `gateway`: 网关 URL（如 "https://arweave.net"）
- `height`: 区块高度

**返回：**
- `*Block`: 区块数据指针
- `error`: 错误信息

#### FetchBlockByHash
通过哈希获取完整区块。

```go
func FetchBlockByHash(gateway, hash string) (*Block, error)
```

#### FetchBlockHeaderByHeight
通过高度获取区块头部（轻量）。

```go
func FetchBlockHeaderByHeight(gateway string, height int64) (*BlockHeader, error)
```

#### FetchBlockHeaderByHash
通过哈希获取区块头部（轻量）。

```go
func FetchBlockHeaderByHash(gateway, hash string) (*BlockHeader, error)
```

### 区块验证

#### VerifyBlockLight
轻量验证区块，仅验证头部信息。

```go
func VerifyBlockLight(gateway string, height int64) (*BlockVerificationResult, error)
```

**特点：**
- 仅获取区块头部数据
- 验证高度、哈希格式等基本信息
- 网络流量极小（约 1 KB）

#### VerifyBlockFull
全量验证区块，包括所有字段。

```go
func VerifyBlockFull(gateway string, height int64) (*BlockVerificationResult, error)
```

#### VerifyBlockHeader
验证区块头部数据。

```go
func VerifyBlockHeader(header *BlockHeader) *BlockVerificationResult
```

### 交易标签获取

#### FetchTransactionTags
轻量获取单个交易的 tags。

```go
func FetchTransactionTags(gateway, txID string) ([]Tag, error)
```

**特点：**
- 使用 `/tx/[id]/tags` 端点
- 仅获取 tags 字段，不获取完整交易数据

#### FetchBlockTransactionTags
轻量获取区块内所有交易的 tags（并发）。

```go
func FetchBlockTransactionTags(gateway string, height int64) (map[string][]Tag, error)
```

**特点：**
- 并发获取所有交易的 tags
- 返回交易 ID 到 tags 的映射
- 使用 sync.Mutex 保护并发访问

#### FetchBlockTransactionTagsLight
轻量获取区块内指定交易的 tags。

```go
func FetchBlockTransactionTagsLight(gateway string, txIDs []string) (map[string][]Tag, error)
```

#### GetBlockTransactionCount
获取区块内的交易数量。

```go
func GetBlockTransactionCount(gateway string, height int64) (int, error)
```

#### GetBlockTransactionIDs
获取区块内的所有交易 ID。

```go
func GetBlockTransactionIDs(gateway string, height int64) ([]string, error)
```

---

## 捆绑包功能

### 捆绑包数据结构

#### Bundle
表示一个完整的 ANS-104 捆绑包。

| 字段 | 类型 | 说明 |
|------|------|------|
| Items | []BundleItem | 捆绑包中的所有数据项 |

#### BundleItem
表示捆绑包中的单个数据项。

| 字段 | 类型 | 说明 |
|------|------|------|
| SignatureType | int | 签名类型（1=Arweave, 2=Ed25519, 3=Ethereum, 4=Solana） |
| Signature | string | Base64 编码的签名 |
| Owner | string | Base64 编码的拥有者公钥 |
| Target | string | 可选的目标交易 ID |
| Anchor | string | 可选的锚点值 |
| Tags | []Tag | 标签数组 |
| Data | string | Base64 编码的数据内容 |
| Id | string | Base64 编码的数据项 ID |

#### BundleIndex
捆绑包索引，包含所有数据项的元信息。

| 字段 | 类型 | 说明 |
|------|------|------|
| ItemsNum | int | 数据项总数 |
| ItemsMeta | []ItemMeta | 每个数据项的元信息 |
| DataStartPos | int | 数据区的起始位置（字节偏移） |

#### ItemMeta
数据项元信息，用于快速定位和验证。

| 字段 | 类型 | 说明 |
|------|------|------|
| Index | int | 数据项索引 |
| Length | int | 数据项二进制长度（字节） |
| Id | string | Base64 编码的数据项 ID |
| Offset | int | 数据项在捆绑包中的字节偏移 |
| SignatureType | int | 签名类型 |

#### SigMeta
签名元数据，定义不同签名类型的参数。

| 字段 | 类型 | 说明 |
|------|------|------|
| SigLength | int | 签名长度（字节） |
| PubLength | int | 公钥长度（字节） |
| SigName | string | 签名算法名称 |

#### 签名类型常量

| 常量 | 值 | 说明 |
|------|-----|------|
| ArweaveSignType | 1 | Arweave 原生 RSA 签名 |
| ED25519SignType | 2 | Ed25519 签名 |
| EthereumSignType | 3 | 以太坊 ECDSA 签名 |
| SolanaSignType | 4 | Solana Ed25519 签名 |

### 捆绑包解析

#### NewBundleParser
创建新的捆绑包解析器。

```go
func NewBundleParser(reader io.ReaderAt) *BundleParser
```

#### ParseBundleHeaderFromURL
从 URL 解析捆绑包头部（使用 HTTP Range 请求）。

```go
func ParseBundleHeaderFromURL(url string) (*BundleParser, error)
```

**特点：**
- 使用多网关容错
- 两次 HTTP Range 请求获取头部
- 第一次获取 32 字节（数据项数量）
- 第二次获取完整头部（32 + N*64 字节）

#### ParseHeader
解析捆绑包头部。

```go
func (p *BundleParser) ParseHeader() error
```

#### GetIndex
返回已解析的捆绑包索引。

```go
func (p *BundleParser) GetIndex() *BundleIndex
```

#### FetchItem
获取指定索引的数据项。

```go
func (p *BundleParser) FetchItem(itemIndex int) (BundleItem, error)
```

#### ParseAll
解析并获取完整的捆绑包数据。

```go
func (p *BundleParser) ParseAll() (Bundle, error)
```

### 捆绑包验证

#### VerifyHeader
验证捆绑包头部的合法性。

```go
func (p *BundleParser) VerifyHeader() error
```

**检查项：**
- 每个数据项的签名类型
- 签名和公钥长度

#### VerifyItem
验证指定数据项的签名和 ID。

```go
func (p *BundleParser) VerifyItem(itemIndex int) error
```

#### VerifyAll
验证捆绑包中的所有数据项。

```go
func (p *BundleParser) VerifyAll() error
```

#### VerifyBundleStructure
验证捆绑包结构（从文件）。

```go
func VerifyBundleStructure(filePath string) error
```

#### VerifyBundleLight
轻量验证捆绑包（从文件）。

```go
func VerifyBundleLight(filePath string) error
```

#### VerifyBundleFull
全量验证捆绑包（从文件）。

```go
func VerifyBundleFull(filePath string) error
```

### 轻量级标签获取

#### FetchItemTags
仅获取指定数据项的标签，不下载完整数据。

```go
func (p *BundleParser) FetchItemTags(itemIndex int) ([]Tag, error)
```

**特点：**
- 使用 HTTP Range 请求按需获取数据
- 仅读取标签相关字节
- 节省带宽

---

## 交易集合功能

### 交易集合数据结构

#### TransactionInfo
交易信息，包含基础信息和标签。

| 字段 | 类型 | 说明 |
|------|------|------|
| TxID | string | 交易 ID |
| Tags | []Tag | 交易标签（指针，不复制） |
| Source | string | 交易来源："block" 或 "bundle" |
| BundleTxID | string | 如果来自捆绑包，记录捆绑包交易 ID |
| ItemIndex | int | 如果在捆绑包内，记录数据项索引 |
| ItemOffset | int | 如果在捆绑包内，记录数据项偏移量 |

#### TransactionSet
交易集合，使用 map 避免重复。

```go
type TransactionSet map[string]*TransactionInfo
```

**特点：**
- 使用指针避免数据复制
- 以交易 ID 为键
- 支持快速查找和筛选

### 获取所有交易

#### FetchAllTransactions
轻量获取区块和捆绑包内所有交易信息和 tags。

```go
func FetchAllTransactions(gateway string, blockHeight int64) (*TransactionSet, error)
```

**特点：**
- 获取区块内所有交易
- 自动检测并解析捆绑包交易
- 使用多网关容错
- 并发获取交易标签
- 返回指针，避免数据复制
- 捆绑包内交易内嵌元数据（偏移量、索引等）

**流程：**
1. 获取区块数据（多网关容错）
2. 并发获取所有交易的 tags
3. 检测捆绑包交易（Bundle-Format tag）
4. 解析捆绑包头部
5. 并发获取捆绑包内所有数据项的 tags
6. 合并所有交易到一个 TransactionSet

### 交易筛选

#### FilterByTagKey
从交易 set 中筛选包含指定 tag Key 的交易。

```go
func FilterByTagKey(transactions *TransactionSet, tagKey string) *TransactionSet
```

**特点：**
- 严格字符串对比
- 大小写敏感
- 返回指针，不复制数据

#### FilterByTagKeyValue
从交易 set 中筛选包含指定 tag Key:Value 的交易。

```go
func FilterByTagKeyValue(transactions *TransactionSet, tagKey, tagValue string) *TransactionSet
```

**特点：**
- 严格字符串对比
- Key 和 Value 都必须完全匹配
- 大小写敏感
- 返回指针，不复制数据

### 合并功能

#### FetchAndFilterByTagKey
获取所有交易并筛选包含指定 tag Key 的交易。

```go
func FetchAndFilterByTagKey(gateway string, blockHeight int64, tagKey string) (*TransactionSet, error)
```

**等价于：**
```go
allTransactions, _ := FetchAllTransactions(gateway, blockHeight)
filtered := FilterByTagKey(allTransactions, tagKey)
```

#### FetchAndFilterByTagKeyValue
获取所有交易并筛选包含指定 tag Key:Value 的交易。

```go
func FetchAndFilterByTagKeyValue(gateway string, blockHeight int64, tagKey, tagValue string) (*TransactionSet, error)
```

**等价于：**
```go
allTransactions, _ := FetchAllTransactions(gateway, blockHeight)
filtered := FilterByTagKeyValue(allTransactions, tagKey, tagValue)
```

---

## 轻量级验证

### 网络流量跟踪

#### TrafficTracker
跟踪网络流量的 HTTP Transport。

```go
type TrafficTracker struct {
    bytesRead int64
    requests  int64
    transport http.RoundTripper
}
```

**方法：**

| 方法 | 说明 |
|------|------|
| NewTrafficTracker() | 创建流量跟踪器 |
| RoundTrip(req) | 实现 http.RoundTripper 接口 |
| GetBytesRead() | 获取已读取的字节数 |
| GetRequestCount() | 获取请求次数 |

**使用示例：**
```go
tracker := NewTrafficTracker()
client := &http.Client{
    Transport: tracker,
    Timeout:   30 * time.Second,
}

// 执行请求
resp, _ := client.Do(req)

// 查看流量
fmt.Printf("流量: %d bytes\n", tracker.GetBytesRead())
fmt.Printf("请求次数: %d\n", tracker.GetRequestCount())
```

### HTTP Range 请求

SDK 使用 HTTP Range 请求实现轻量级数据获取：

#### 捆绑包头部解析
1. **第一次请求**：获取前 32 字节（数据项数量）
2. **第二次请求**：获取完整头部（32 + N*64 字节）

**流量示例：**
- 45 个数据项的捆绑包
- 第一次请求：32 bytes
- 第二次请求：2,912 bytes
- 总流量：2,944 bytes (2.88 KB)
- 流量效率：98.91%

#### 区块头部验证
- 使用 Range: bytes=0-4095
- 仅获取必要的头部字段
- 流量约 1 KB

---

## 使用示例

### 区块轻量验证

```go
package main

import (
    "fmt"
    "github.com/LWDJD/ipfar-sdk/verify/arweave"
)

func main() {
    result, err := arweave.VerifyBlockLight("https://arweave.net", 100)
    if err != nil {
        fmt.Printf("验证失败: %v\n", err)
        return
    }

    fmt.Printf("区块高度: %d\n", result.Height)
    fmt.Printf("独立哈希: %s\n", result.IndepHash)
    fmt.Printf("验证结果: %v\n", result.IsValid)
}
```

### 获取区块交易标签

```go
package main

import (
    "fmt"
    "github.com/LWDJD/ipfar-sdk/verify/arweave"
)

func main() {
    // 获取单个交易标签
    tags, err := arweave.FetchTransactionTags("https://arweave.net", "txID")
    if err != nil {
        fmt.Printf("获取失败: %v\n", err)
        return
    }

    for _, tag := range tags {
        fmt.Printf("%s = %s\n", tag.Name, tag.Value)
    }

    // 获取区块内所有交易标签
    allTags, err := arweave.FetchBlockTransactionTags("https://arweave.net", 100)
    if err != nil {
        fmt.Printf("获取失败: %v\n", err)
        return
    }

    for txID, tags := range allTags {
        fmt.Printf("交易 %s 有 %d 个标签\n", txID, len(tags))
    }
}
```

### 捆绑包头部解析

```go
package main

import (
    "fmt"
    "github.com/LWDJD/ipfar-sdk/verify/arweave"
)

func main() {
    txID := "jXN3mTRx5oLuOkfbGxy6DTqw1CS_X25cEJ-ASyrE8is"
    url := fmt.Sprintf("https://arweave.net/raw/%s", txID)

    parser, err := arweave.ParseBundleHeaderFromURL(url)
    if err != nil {
        fmt.Printf("解析失败: %v\n", err)
        return
    }

    index := parser.GetIndex()
    fmt.Printf("数据项数量: %d\n", index.ItemsNum)
    fmt.Printf("数据区起始位置: %d\n", index.DataStartPos)

    for _, meta := range index.ItemsMeta {
        fmt.Printf("数据项 %d: ID=%s, 长度=%d, 偏移=%d\n",
            meta.Index, meta.Id, meta.Length, meta.Offset)
    }
}
```

### 获取所有交易并筛选

```go
package main

import (
    "encoding/base64"
    "fmt"
    "github.com/LWDJD/ipfar-sdk/verify/arweave"
)

func main() {
    // 获取所有交易
    transactions, err := arweave.FetchAllTransactions("https://arweave.net", 100)
    if err != nil {
        fmt.Printf("获取失败: %v\n", err)
        return
    }

    fmt.Printf("总交易数: %d\n", len(*transactions))

    // 按 Tag Key 筛选
    tagKey := "QnVuZGxlLUZvcm1hdA" // Bundle-Format
    filtered := arweave.FilterByTagKey(transactions, tagKey)
    fmt.Printf("包含 %s 的交易数: %d\n", tagKey, len(*filtered))

    // 按 Tag Key:Value 筛选
    tagValue := "YmluYXJ5" // binary
    filtered2 := arweave.FilterByTagKeyValue(transactions, tagKey, tagValue)
    fmt.Printf("包含 %s:%s 的交易数: %d\n", tagKey, tagValue, len(*filtered2))

    // 打印交易详情
    for txID, txInfo := range *transactions {
        fmt.Printf("\n交易 ID: %s\n", txID)
        fmt.Printf("  来源: %s\n", txInfo.Source)
        if txInfo.Source == "bundle" {
            fmt.Printf("  捆绑包: %s\n", txInfo.BundleTxID)
            fmt.Printf("  数据项索引: %d\n", txInfo.ItemIndex)
            fmt.Printf("  数据项偏移量: %d\n", txInfo.ItemOffset)
        }

        for _, tag := range txInfo.Tags {
            name, _ := base64.RawURLEncoding.DecodeString(tag.Name)
            value, _ := base64.RawURLEncoding.DecodeString(tag.Value)
            fmt.Printf("  标签: %s = %s\n", string(name), string(value))
        }
    }
}
```

### 合并获取和筛选

```go
package main

import (
    "fmt"
    "github.com/LWDJD/ipfar-sdk/verify/arweave"
)

func main() {
    // 一步完成获取和筛选
    tagKey := "QnVuZGxlLUZvcm1hdA"
    filtered, err := arweave.FetchAndFilterByTagKey("https://arweave.net", 100, tagKey)
    if err != nil {
        fmt.Printf("获取失败: %v\n", err)
        return
    }

    fmt.Printf("匹配交易数: %d\n", len(*filtered))

    // 按 Key:Value 筛选
    tagValue := "YmluYXJ5"
    filtered2, err := arweave.FetchAndFilterByTagKeyValue("https://arweave.net", 100, tagKey, tagValue)
    if err != nil {
        fmt.Printf("获取失败: %v\n", err)
        return
    }

    fmt.Printf("匹配交易数: %d\n", len(*filtered2))
}
```

### 网络流量测量

```go
package main

import (
    "fmt"
    "net/http"
    "github.com/LWDJD/ipfar-sdk/verify/arweave"
)

func main() {
    tracker := arweave.NewTrafficTracker()
    client := &http.Client{
        Transport: tracker,
        Timeout:   30 * time.Second,
    }

    // 执行请求
    req, _ := http.NewRequest("GET", "https://arweave.net/raw/txID", nil)
    req.Header.Set("Range", "bytes=0-31")
    resp, _ := client.Do(req)
    defer resp.Body.Close()

    // 读取数据
    data := make([]byte, 32)
    io.ReadFull(resp.Body, data)

    fmt.Printf("请求次数: %d\n", tracker.GetRequestCount())
    fmt.Printf("网络流量: %d bytes\n", tracker.GetBytesRead())
}
```

---

## 附录

### 默认网关

SDK 提供多网关容错机制，默认网关列表：

| 网关 | URL |
|------|-----|
| 主网关 | https://arweave.net |
| 备用 1 | https://ar-io.net |
| 备用 2 | https://gateway.irys.xyz |

### ANS-104 捆绑包头部格式

| 偏移 | 长度 | 说明 |
|------|------|------|
| 0 | 32 | 数据项数量（小端序） |
| 32 | N*64 | 数据项元信息（每项 64 字节） |
| 32+N*64 | 可变 | 数据区 |

每个数据项元信息（64 字节）：
- 前 32 字节：数据项二进制长度（小端序）
- 后 32 字节：数据项 ID（Base64 解码后的字节）

### Tag 编码格式

Tag 使用 Apache Avro 编码：
- VInt（变长整数）编码
- ZigZag 编码支持负数
- 数组块结构

### 文件列表

| 文件 | 说明 |
|------|------|
| bundle.go | ANS-104 捆绑包解析和验证 |
| block.go | 区块解析和验证 |
| transaction_set.go | 交易集合管理和筛选 |
| lightweight_test.go | 轻量级操作和流量测试 |
| bundle_test.go | 捆绑包测试 |
| block_test.go | 区块测试 |
| transaction_set_test.go | 交易集合测试 |
