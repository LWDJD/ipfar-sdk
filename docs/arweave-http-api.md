# Arweave HTTP API 文档

## 概述

Arweave 协议基于 HTTP，因此任何现有的 HTTP 客户端/库都可以与网络交互。

- **默认端口**: 1984
- **请求方式**: 可以直接向任何 Arweave 节点的 IP 地址发送请求，例如 `http://159.65.213.43:1984/info`
- **域名访问**: 如果配置了 DNS，也可以使用主机名，例如 `https://arweave.net/info`

## API 端点列表

### 1. 网络信息

#### GET /info

获取当前节点的网络信息。

**请求示例**:
```bash
curl https://arweave.net/info
```

**响应示例**:
```json
{
  "network": "arweave.N.1",
  "version": "3",
  "height": "2956",
  "blocks": "3495",
  "peers": "12"
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| network | string | 网络名称 |
| version | string | 节点版本 |
| height | string | 当前区块高度 |
| blocks | string | 区块数量 |
| peers | string | 对等节点数量 |

---

### 2. 交易相关 API

#### GET /tx/[transaction_id]

通过交易 ID 获取完整的 JSON 交易记录。

**路径参数**:
- `transaction_id`: Base64 编码的交易 ID

**请求示例**:
```bash
curl https://arweave.net/tx/VvNF3aLS28MXD_o4Lv0lF9_WcxMibFOp166qDqC1Hlw
```

**响应示例**:
```json
{
  "id": "VvNF3aLS28MXD_o4Lv0lF9_WcxMibFOp166qDqC1Hlw",
  "last_tx": "bUfaJN-KKS1LRh_DlJv4ff1gmdbHP4io-J9x7cLY5is",
  "owner": "1Q7RfP...J2x0xc",
  "tags": [],
  "target": "",
  "quantity": "0",
  "data": "3DduMPkwLkE0LjIxM9o",
  "reward": "1966476441",
  "signature": "RwBICn...Rxqi54"
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| id | string | 交易 ID |
| last_tx | string | 上一个交易 ID |
| owner | string | 拥有者公钥 |
| tags | array | 标签数组 |
| target | string | 目标地址（转账交易） |
| quantity | string | 转账数量（winston） |
| data | string | Base64 编码的数据 |
| reward | string | 挖矿奖励（winston） |
| signature | string | 交易签名 |

---

#### GET /tx/[transaction_id]/status

获取交易的确认状态信息。

**路径参数**:
- `transaction_id`: Base64URL 编码的交易 ID

**请求示例**:
```bash
curl https://arweave.net/tx/VvNF3aLS28MXD_o4Lv0lF9_WcxMibFOp166qDqC1Hlw/status
```

**响应示例**:
```json
{
  "block_indep_hash": "KCdtB29b5V0rz2hX_sSGfEd5Fw7iTEiuXp5M34dWPEIdhxPqf3rsNyRFUznAhDzb",
  "block_height": 10,
  "number_of_confirmations": 3
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| block_indep_hash | string | 区块独立哈希 |
| block_height | number | 区块高度 |
| number_of_confirmations | number | 确认数 |

---

#### GET /tx/[transaction_id]/[field]

获取交易的特定字段。

**路径参数**:
- `transaction_id`: Base64URL 编码的交易 ID
- `field`: 字段名称，可选值：`id` | `last_tx` | `owner` | `target` | `quantity` | `data` | `reward` | `signature`

**请求示例**:
```bash
curl https://arweave.net/tx/VvNF3aLS28MXD_o4Lv0lF9_WcxMibFOp166qDqC1Hlw/last_tx
```

**响应示例**:
```
"bUfaJN-KKS1LRh_DlJv4ff1gmdbHP4io-J9x7cLY5is"
```

---

#### GET /tx/[transaction_id]/data.html

获取交易数据并解码为 HTML 格式。如果交易是存档的网站，结果将是可在浏览器中渲染的 HTML。

**路径参数**:
- `transaction_id`: Base64URL 编码的交易 ID

**请求示例**:
```bash
curl https://arweave.net/tx/B7j_bkDICQyl_y_hBM68zS6-p8-XiFCUmEBaXRroFTM/data.html
```

**响应示例**:
```html
Hello World
```

---

#### GET /tx/[transaction_id]/offset

获取交易的偏移量和大小信息。用于确定交易数据在 Weave 中的位置。

**路径参数**:
- `transaction_id`: Base64URL 编码的交易 ID

**请求示例**:
```bash
curl https://arweave.net/tx/VvNF3aLS28MXD_o4Lv0lF9_WcxMibFOp166qDqC1Hlw/offset
```

**响应示例**:
```json
{
  "offset": "1234567890",
  "size": "1024"
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| offset | string | 交易数据在 Weave 中的偏移量 |
| size | string | 交易数据大小（字节） |

---

#### POST /tx

向网络提交交易。

**请求体**:
```json
{
  "id": "VvNF3aLS28MXD_o4Lv0lF9_WcxMibFOp166qDqC1Hlw",
  "last_tx": "bUfaJN-KKS1LRh_DlJv4ff1gmdbHP4io-J9x7cLY5is",
  "owner": "1Q7RfP...J2x0xc",
  "tags": [],
  "target": "",
  "quantity": "0",
  "data": "3DduMPkwLkE0LjIxM9o",
  "reward": "1966476441",
  "signature": "RwBICn...Rxqi54"
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| id | string | 交易 ID |
| last_tx | string | 钱包的最后一个交易 ID（首次交易为空） |
| owner | string | 发起交易的公钥 |
| tags | array | 标签数组 |
| target | string | 接收方地址（Base64 编码的 SHA256 哈希，数据交易为空） |
| quantity | string | 发送的 AR 数量（winston，数据交易为空） |
| data | string | Base64 编码的存储数据（转账交易为空） |
| reward | string | 挖矿奖励（winston） |
| signature | string | Base64 编码的交易签名 |

**注意**: 所有 winston 值字段（quantity 和 reward）都是字符串，以允许不支持任意精度算术的环境进行互操作。

---

### 3. 区块相关 API

#### GET /block/hash/[block_id]

通过区块哈希获取区块信息。

**路径参数**:
- `block_id`: Base64URL 编码的区块独立哈希（indep_hash）

**请求头**:
- `Accept`: application/json
- `X-Block-Format`: 可选，指定区块格式

**请求示例**:
```bash
curl https://arweave.net/block/hash/oyxTcYAgbbNoFyDz8hqs7KCJHI4qb4VdER9Jotbs
```

**响应示例**:
```json
{
  "nonce": "c7V-8dLmmqo",
  "previous_block": "yeCiFpWcguWtWRJnJ_XOKhQXw6xtiOHh-rAw-RjX0YE",
  "timestamp": 1517563547,
  "last_retarget": 1517563547,
  "diff": 8,
  "height": 30,
  "hash": "-3-oyxTcYAgbbNoFyDz8hqs7KCJHI4qb4VdER9Jotbs",
  "indep_hash": "oyxTcYAgbbNoFyDz8hqs7KCJHI4qb4VdER9Jotbs",
  "txs": [...],
  "hash_list": [...],
  "wallet_list": [...],
  "reward_addr": "unclaimed"
}
```

---

#### GET /block/height/[block_height]

通过区块高度获取区块信息。

**路径参数**:
- `block_height`: 请求的区块高度

**请求示例**:
```bash
curl https://arweave.net/block/height/1101
```

**响应示例**:
```json
{
  "nonce": "c7V-8dLmmqo",
  "previous_block": "yeCiFpWcguWtWRJnJ_XOKhQXw6xtiOHh-rAw-RjX0YE",
  "timestamp": 1517563547,
  "last_retarget": 1517563547,
  "diff": 8,
  "height": 30,
  "hash": "-3-oyxTcYAgbbNoFyDz8hqs7KCJHI4qb4VdER9Jotbs",
  "indep_hash": "oyxTcYAgbbNoFyDz8hqs7KCJHI4qb4VdER9Jotbs",
  "txs": [...],
  "hash_list": [...],
  "wallet_list": [...],
  "reward_addr": "unclaimed"
}
```

---

#### GET /current_block

获取当前区块（网络头部）的信息。

**请求示例**:
```bash
curl https://arweave.net/current_block
```

**响应示例**:
```json
{
  "nonce": "rihlezm7XAc",
  "previous_block": "pc-0MvV6lQOWt0O2L3VcSheOfIdymntOBVcloERVbQQ",
  "timestamp": 1517564276,
  "last_retarget": 1517564044,
  "diff": 24,
  "height": 166,
  "hash": "mGe34a3DcT8HLE0BfaME38XUelENSjPQA-vcYJG6PGs",
  "indep_hash": "ntoWN8DMFSuxPsdF8CelZqP03Gr4GahMBXX8ZkyPA3U",
  "txs": [...],
  "hash_list": [...],
  "wallet_list": [...],
  "reward_addr": "unclaimed"
}
```

---

### 4. 钱包相关 API

#### GET /wallet/[wallet_address]/balance

获取指定钱包地址的余额。

**路径参数**:
- `wallet_address`: Base64URL 编码的 RSA 模数原始 SHA256 哈希

**请求示例**:
```bash
curl https://arweave.net/wallet/VukPk7P3qXAS2Q76ejTwC6Y_U_bMl_z6mgLvgSUJIzE/balance
```

**响应示例**:
```
"1249611338095239"
```

返回的余额单位为 winston（AR 的最小单位，1 AR = 1000000000000 winston）。

---

#### GET /wallet/[wallet_address]/last_tx

获取指定地址的最后一个交易 ID。

**路径参数**:
- `wallet_address`: Base64 编码的公钥 SHA256 哈希

**请求示例**:
```bash
curl https://arweave.net/wallet/VukPk7P3qXAS2Q76ejTwC6Y_U_bMl_z6mgLvgSUJIzE/last_tx
```

**响应示例**:
```
"bUfaJN-KKS1LRh_DlJv4ff1gmdbHP4io-J9x7cLY5is"
```

---

#### GET /wallet/[wallet_address]/txs/[earliest_tx]

获取指定钱包发起的交易标识符列表。

**路径参数**:
- `wallet_address`: Base64 编码的公钥 SHA256 哈希
- `earliest_tx` (可选): Base64 编码的最早交易 ID。如果未指定，则返回该钱包发起的所有交易。

**请求示例**:
```bash
curl https://arweave.net/wallet/VukPk7P3qXAS2Q76ejTwC6Y_U_bMl_z6mgLvgSUJIzE/txs/bUfaJN-KKS1LRh_DlJv4ff1gmdbHP4io-J9x7cLY5is
```

**响应示例**:
```json
["bUfaJN-KKS1LRh_DlJv4ff1gmdbHP4io-J9x7cLY5is", "b23...xg"]
```

---

#### GET /wallet/[wallet_address]/deposits/[earliest_deposit]

获取发送到指定地址的转账交易标识符列表。索引是部分的 - 仅返回该节点已知的交易。

**路径参数**:
- `wallet_address`: Base64 编码的公钥 SHA256 哈希
- `earliest_deposit` (可选): Base64 编码的最早存款交易 ID。如果未指定，则获取该节点已知的所有存款。

**请求示例**:
```bash
curl https://arweave.net/wallet/VukPk7P3qXAS2Q76ejTwC6Y_U_bMl_z6mgLvgSUJIzE/deposits
```

**响应示例**:
```json
["bUfaJN-KKS1LRh_DlJv4ff1gmdbHP4io-J9x7cLY5is", "b23...xg"]
```

---

### 5. 价格相关 API

#### GET /price/[byte_size]

获取指定大小交易的预估价格。

**路径参数**:
- `byte_size`: 交易数据字段的大小（字节）。对于没有关联数据的金融交易，这应该是零。

**请求示例**:
```bash
curl https://arweave.net/price/2048
```

**响应示例**:
```
"1896296296"
```

返回的金额单位为 winston。该端点是悲观的，它报告的价格假设网络难度小 1，以考虑可能的难度变化。

---

### 6. 数据获取 API

#### GET /[transaction_id]

直接通过交易 ID 获取原始数据。这是获取存储在 Arweave 上的数据的主要方式。

**路径参数**:
- `transaction_id`: Base64URL 编码的交易 ID

**请求示例**:
```bash
curl https://arweave.net/VvNF3aLS28MXD_o4Lv0lF9_WcxMibFOp166qDqC1Hlw
```

**响应**: 交易的原始数据（自动解码）

---

#### GET /raw/[transaction_id]

获取交易的原始二进制数据，不进行任何内容协商。

**路径参数**:
- `transaction_id`: Base64URL 编码的交易 ID

**请求示例**:
```bash
curl https://arweave.net/raw/VvNF3aLS28MXD_o4Lv0lF9_WcxMibFOp166qDqC1Hlw
```

**响应**: 交易的原始二进制数据

---

#### GET /chunk/[offset]

获取指定偏移量的数据块。用于流式获取大型交易数据。

**路径参数**:
- `offset`: 数据块的偏移量

**请求示例**:
```bash
curl https://arweave.net/chunk/1234567890
```

**响应**: 指定偏移量的数据块

---

### 7. 节点相关 API

#### GET /peers

获取节点的对等节点列表。

**请求示例**:
```bash
curl https://arweave.net/peers
```

**响应示例**:
```json
[
  "127.0.0.1:1985",
  "127.0.0.1:1986"
]
```

返回包含该节点所有对等节点 IP 地址的列表。

---

### 8. HTTP Range 请求支持

Arweave 网关支持 HTTP Range 请求，用于按需获取大型交易数据的部分内容。

**请求示例**:
```bash
curl -H "Range: bytes=0-1023" https://arweave.net/raw/VvNF3aLS28MXD_o4Lv0lF9_WcxMibFOp166qDqC1Hlw
```

**响应头**:
```
HTTP/1.1 206 Partial Content
Content-Range: bytes 0-1023/1048576
Content-Length: 1024
```

---

## 区块数据结构

区块结构随着协议升级有所变化，以下是不同版本的区块结构：

### 早期区块结构 (height: 100)

```json
{
  "nonce": "AAEBAAABAQAAAQAAAQEBAAEAAAABAQABAQABAAEAAAEBAAAAAQAAAAAAAQAAAQEBAAEBAAEBAQEBAQEAAQEBAAABAQEAAQAAAQABAAABAAAAAAEBAQEBAAABAQEAAAAAAAABAQAAAQAAAQEAAQABAQABAQEAAAABAAABAQABAQEAAAEBAQABAQEBAQEBAAABAQEAAAABAQABAAABAAEAAQEBAQAAAAABAQABAQAAAAAAAAABAQABAAEBAAEAAQABAQABAAEBAQEBAAEAAQABAAABAQEBAQAAAQABAQEBAAEBAQAAAQEBAQABAAEBAQEBAAAAAAABAAEAAAEAAAEAAAEBAAAAAAEAAQABAAAAAAABAQABAQAAAAEBAQAAAAABAAABAAEBAQEAAAAAAQAAAQABAQABAAEAAQABAQAAAAEBAQAAAQAAAAEBAAEBAAEBAQEAAAEBAQAAAQAAAAABAAEAAQEAAQ",
  "previous_block": "V6YjG8G3he0JIIwRtzTccX39rS0jH-jOqUJy6rxrVAHY0RT0AVhG8K22wCDxy1A0",
  "timestamp": 1528500720,
  "last_retarget": 1528500720,
  "diff": 31,
  "height": 100,
  "hash": "AAAAANsEvzGbICpfAj3NN41_ox--2cNxkEhAo0aggpDPkY7zru29g24uMWUP9hTa",
  "indep_hash": "",
  "txs": ["7BoxcxiJIjTwUp3JXp0xRJQXf6hZtyJj1kjGNiEl5A8"],
  "wallet_list": "ph2FDDuQjNbca34tz7vP9X5Xve2EGJi2ZgFqhMITAdw",
  "reward_addr": "em8MfGRInwWEAQnE6b50ENaFOf-0to4Pbygng1ilWGQ",
  "tags": [],
  "reward_pool": 60770606104,
  "weave_size": 599058,
  "block_size": 0
}
```

### 中期区块结构 (height: 269512)

```json
{
  "nonce": "O3IQWXYmxLN_b0w7QyT2GTruaVIGsl-Ybhc6Pl2V20U",
  "previous_block": "VRVYubqppWUVAeCWlzHR-38dQoWcFAKbGculkVZThfj-hNMX4QVZjqkC6-PkiNGE",
  "timestamp": 1567052949,
  "last_retarget": 1567052114,
  "diff": "115792088374597902074750511579343425068641803109251942518159264612597601665024",
  "height": 269512,
  "hash": "____47liyh_OZdYUP4EzBoLl7JOPge9VsWPQ3b5kiU8",
  "indep_hash": "5H-hJycMS_PnPOpobXu2CNobRlgqmw4yEMQSc5LeBfS7We63l8HjS-Ek3QaxK8ug",
  "txs": [
    "tqDWYT-qdoCeSWGpV2Ig48lpswOxccbBpyxf0GQjs2U",
    "y0bIjxLaXu1gEjpRlyPUh0Uz0c5XrhIOs6z4lerXo8w"
  ],
  "wallet_list": "6haahtRP5WVchxPbqtLCqDsFWidhebYJpU5PVB4zQhE",
  "reward_addr": "aE1AjkBoXBfF-PRP2dzRrbYY8cY2OYzeH551nSPRU5M",
  "tags": [],
  "reward_pool": 0,
  "weave_size": 21080508475,
  "block_size": 991723,
  "cumulative_diff": "616416144",
  "hash_list_merkle": "1QVbbLwZHpNMJd8ZghRb13HZfrRu-aIIfzY29r64_yBJAcYv-Kfblv_c2pfKbQBP"
}
```

### 现代区块结构 (height: 422250+)

```json
{
  "nonce": "W3Jy4wp2LVbDFhGX_hUjRQZCkTdEbKxz45E5OVe52Lo",
  "previous_block": "YuTyalVBTNB9t5KhuRezcIgxVz9PbQsbrcY4Tpkiu8XBPgglGM_Yql5qZd0c9PVG",
  "timestamp": 1586440919,
  "last_retarget": 1586440919,
  "diff": "115792089039110416381168389782714091630053560834545856346499935466490404274176",
  "height": 422250,
  "hash": "_____8422fLZnBsEsxtwEdpi8GZDHVT-aFlqroQDG44",
  "indep_hash": "5VTARz7bwDO4GqviCSI9JXm8_JOtoQwF-QCZm0Gt2gVgwdzSY3brOtOD46bjMz09",
  "txs": ["IRPCjc_ws7aS5GWp4mwR2k-HuQy-zT_GWrgR6kRdbmI"],
  "tx_root": "lsoo-p3Tj7oblZ-54WVPHoVguqgw5rA9Jf3lLH6H8zY",
  "tx_tree": [],
  "wallet_list": "N5NJtXhgH9bPmXoSopehcr_zqwyPjjg3igel0V8G1DdLk_BYdoRVIBsqjVA9JmFc",
  "reward_addr": "Oox7m4HIcVhUtMd6AUuGtlaOoSCmREUNPyyKQCbz4d4",
  "tags": [],
  "reward_pool": 3026104059201252,
  "weave_size": 407672420044,
  "block_size": 937455,
  "cumulative_diff": "99416580392277",
  "hash_list_merkle": "akSjDrBKPuepJMOhO_S9C-iFp5zn9Glv57HGdN_WPqEToWC0Ukb37Gzs4PDA7oLU",
  "poa": {
    "option": "1",
    "tx_path": "xZ6vhVXw_0BlD-Xkv3KtfnJeLXykjkjUrwcPsXw2JUnie021At7I-fMZkt5EF_xOHtcdq4RIqXto1gwFAM5eZg...",
    "data_path": "bTVpffiN3SSDeqBEJpKiXegQGKKnprS_AFMh6zz4QRIU-8dJuvFzyKxqjkDHQvtKl0Eajfm18yZsjaAJkNhbAw...",
    "chunk": "aHQ6OTBweH1AbWVkaWEgKG1pbi13aWR0aDo3NjhweCkgYW5kIChtYXgtd2lkdGg6MTA..."
  }
}
```

### 最新区块结构 (height: 812970+)

```json
{
  "usd_to_ar_rate": ["1", "65"],
  "scheduled_usd_to_ar_rate": ["1", "65"],
  "packing_2_5_threshold": "30581055168778",
  "strict_data_split_threshold": "30607159107830",
  "nonce": "byirx1oc0-_7YhQn-ALGBgAAVKmh8Bgmp7OyLtvgruk",
  "previous_block": "R58RTTzEKmSyaqhRik4fvl9AkN3g98QEntvZuoly02uwm8J4fZbcvgv9wEEgN5Ne",
  "timestamp": 1637154761,
  "last_retarget": 1637154761,
  "diff": "115792089200990798889969750100406950138692751005015780350441187278229868977849",
  "height": 812970,
  "hash": "_____6737DxIc6c3tMtRsYRgDfdgOODK83odB3ziOTg",
  "indep_hash": "nIq5881hbLMH5vPsv0mwrP6Je-4-0fp0AOSf2UbsQ1jnoA3SfSOYZm4dd6X3g2lu",
  "txs": ["4EsvhIGP6u6GR-kEHdUVhHYYJJyKkV-AGJGHKsVlrGI", ...],
  "tx_root": "AQP-SjJY8MtBMMFBBbJU1Eoxn6CD5Bh0Z4B6tW1V1IY",
  "wallet_list": "UO7vrGy8Utyw1dwquK4l3Rs066EJ0i7ajoFNC7L20h-9VXWbjl56TmPT_yWnWakF",
  "reward_addr": "-GMnn4oswztJB548o6o9ctdTLHg8Mpusn943kZXhaJM",
  "tags": [],
  "reward_pool": "27384655909087787",
  "weave_size": "30607610781942",
  "block_size": "451674112",
  "cumulative_diff": "2951089982733595",
  "hash_list_merkle": "GgXDIzoQ41V3ZM-VQotjH3IpzwJy_DAh2mfk_yyXPBkNgZ5anApDmsIOr7H43_ZG",
  "poa": {
    "option": "1",
    "tx_path": "e2ipAYDKa-YunBFWV99cSIzGV9FO1aTxaXCtKmPtai5PpzADXBf1BLtDBp2ciPIZFHl0oS-KjDWWgxhv-Bda8...",
    "data_path": "lbOSqGDAcekqm0ULAHcSIQQrWR3p22Z9K6i4Tr02mEPs5bthSxAWERDrkAXYUpaN8emeQOaZELzH74xQTH6-4...",
    "chunk": "4FY69JenKk-loETCL7wTv3DGzCkVjTV8x8Mo5w2vxz_mKs4YX8PsB-m..."
  }
}
```

### 最新区块结构 (height: 1132210+)

```json
{
  "hash_preimage": "zxjxIc7BEGfCZOvhA599qRjuVfnTjnTPP4r2SVnn44I",
  "recall_byte": "20038419977588",
  "reward": "1465707980036",
  "previous_solution_hash": "______DyF1XD_nHsnEh6pdyYJ-0oHn0DCUyqN4Akkx8",
  "partition_number": 5,
  "nonce_limiter_info": {
    "output": "s2a28R-wRiQ-iM53XsYcgydB6sxj1QvDT4SYdBWcW1M",
    "global_step_number": 80,
    "seed": "AM7rbYBtYzJMmX9D5A6LEPAAE02yN-4LzsSKAk459Lpao_M0JUhUK_53Yp6_7bNb",
    "next_seed": "gMsCnK2EimYg8wvEt7BvOFvyFLZGsu5HSJ48cpTklxyzYsMB2E3NDRRAv4mTD1jb",
    "zone_upper_bound": 134783121793270,
    "next_zone_upper_bound": 134792922570998,
    "prev_output": "oJJOt_1wU0qGKC23r95R-OuL5ei_Z4XJrGGG2NPl9qk",
    "last_step_checkpoints": ["s2a28R-wRiQ-iM53XsYcgydB6sxj1QvDT4SYdBWcW1M", ...],
    "checkpoints": ["s2a28R-wRiQ-iM53XsYcgydB6sxj1QvDT4SYdBWcW1M", ...]
  },
  "poa2": { "option": "1", "tx_path": "", "data_path": "", "chunk": "" },
  "signature": "Ygl9YMlJMrD_lphxulN_n1Y0FJI8OcjvoPcScgZWvhGtg5zTj9Y9LZYREwZrF4PgUq0ktVeYlG4i-Qv1z1QJYgSn7FMX-8SWvjBzgGERdmyxWSeF-DtAwU3JiiInrtilZDZmw3y0QzXKwyzysUeWXQoL1B2Kj0N9swvuENJmiqfY7yWmvUlTFQO-AHr5FHrHRadH3dMrpbNJ4GlithNmNACjBYiqGnrwxH62d_gdc13G4MG3frITkX8lPf5KPAwenUNE2UZ9kv3Yyihog2PXH7x1lx5dfDBCb8uVsNsNxgHAud1krNpNO8ycq2L6-fmEEvAUvsf-YBqeCXjtMYPacOwzWsmPF--6Ed9VT_Om6mGGf0_XZjzuoDl7vQiafdpgW8dtW9qJD8cCmgf_63pltEDRxSkEp_COho293NR84ggN8sJGbXKH0EBFTIAa_ce-hgUy9wP4e18hoLHVLHK737HpJsaxBLoA-JrOUpWoCGT2T910NrIqMo9G-Wsy7xEiSVPaJGfmU4sRJJcjGAj84U4TPp4XJGYps8n-DdW3C2ZA5xCf7fw8Ic7H1JXqYiGUo3isKYkUD7w-7V_FezcnJ7D_znTH5rfkuEvdp3w3f-ZHyKNCdVIC9m2qC-rVOtOOfwAQtRKBK6T8PYpiQLvg3soOVAqIDoGWRVLe8kIqMl8",
  "reward_key": "2LWWYCT6WKJ_AJoxGqicO5gyLg_joq6kHEU_4K-nPcA3dMCZWs7hDkyQcsFrk5sCtSmjJ2C4Rf1M54jLb21-kSE6rxMYZeWtJDldsFuUyEJ8y99p8MWLQohno9t1BDM9cBVIQh4sbV6A8_P4ICv-rTnVfG2YIfGzsz044vUm3kqKXFJW44kBksoktuXOGVPR0ak03TfKu1PgzHm23Ms4u4Ug3-yyDGoNWrHkCkDf3BIxG8lGHc_UrkjN16oG8UgJviyKzZMg59HBgcUeSrgAnSW36zCtFC03_fpfvA0VQpKPFmVFXNts1bMoyUkW2oCvQMhE-iNQkUwv79BO3_NxZZpqLk7HlfB6gQ_0fxHoEIpUnjM8-PRVNFQCHNZ8zdyCHmEZtA2SLlxocLmA5VNyjNChAThT-xYnNijbLLfs1FHjEV4Q_2PYcvV4w8R9hYcveexgRvEc69dEwM3i9Op9QPVX53u0Wi0bqfnHoVZnrNbIJWbpWrLxwHN2j097QaPl-83Pzg63kF6bkyLlpKNMW6sjGSGOOR1yrnUUUnRrM_t_7BD5ZpKoobcQDcwjuUSzIf_ypz51SytPSEL0Kh8-oK5BPEEpvcAuEoZh-X0EXInIKW0eTRn5G9JiuCydHXy4SKwZBhGvTHHY_ZdynOlKPMNYyt05V9DIqno5DlxCLNk",
  "price_per_gib_minute": "6986",
  "scheduled_price_per_gib_minute": "6986",
  "reward_history_hash": "I190QrZCm05s9aIbt9j6bjFJn1BkNvZVMPEXJ7QFTtI",
  "debt_supply": "0",
  "kryder_plus_rate_multiplier": "1",
  "kryder_plus_rate_multiplier_latch": "0",
  "denomination": "1",
  "redenomination_height": 0,
  "double_signing_proof": {},
  "previous_cumulative_diff": "4369104305356760",
  "usd_to_ar_rate": ["8855", "524288"],
  "scheduled_usd_to_ar_rate": ["1", "10"],
  "packing_2_5_threshold": "0",
  "strict_data_split_threshold": "30607159107830",
  "nonce": "AQ8",
  "previous_block": "gMsCnK2EimYg8wvEt7BvOFvyFLZGsu5HSJ48cpTklxyzYsMB2E3NDRRAv4mTD1jb",
  "timestamp": 1678092233,
  "last_retarget": 1678092233,
  "diff": "115792084401224566807772651152730092358388734887252574358647557874619658061534",
  "height": 1132210,
  "hash": "____09aYjKvcwjKp_Qb444oIiJVpbSxJF3o21jBOwFU",
  "indep_hash": "7OkBVCwRpf-w5B-yKClukNEzDbyV4Cs1Jlc65WmL-uR4gu6ZisocC2gHufg0wHVe",
  "txs": ["fzuqZGVS5FvX_EsSxAB670ZLYT4cWGI8Ais-CeF7Sc4", ...],
  "tx_root": "jHMSGnQUPqGM21zwVi2EFpJrHmjrLDqyavxodjC61mw",
  "wallet_list": "Y17X1la5YZWup2Q0tn7YQVizb8fs2R8OY1KUmqLayeU_SBEEDTHp9PgtR_90kWS3",
  "reward_addr": "SOtIrcaiJwVs4h3yqXKjOs0P9bNJG5F77y0-TilnQ2U",
  "tags": [],
  "reward_pool": "46030523196756537",
  "weave_size": "134792975261942",
  "block_size": "52690944",
  "cumulative_diff": "4369104329300079",
  "hash_list_merkle": "iMx_IwEe6lEGXGBqFr0NXl5AtQYPb9HILU8FD3nNqXvoqgqvoriXTiSeW7PmtCtF",
  "poa": {
    "option": "1",
    "tx_path": "mTA_E-nj8VL4XjyQp0PX8wmQYHqTTBQ-TQR9p8ySBK9WNjzAci0Wh9FgYIjVgSNhtNz-G8dJfPz-1L1DOoiDIA...",
    "data_path": "lbOSqGDAcekqm0ULAHcSIQQrWR3p22Z9K6i4Tr02mEPs5bthSxAWERDrkAXYUpaN8emeQOaZELzH74xQTH6-4...",
    "chunk": "4FY69JenKk-loETCL7wTv3DGzCkVjTV8x8Mo5w2vxz_mKs4YX8PsB-m..."
  }
}
```

## 区块字段说明

| 字段 | 类型 | 说明 |
|------|------|------|
| `nonce` | string | 工作量证明的随机数 |
| `previous_block` | string | 前一个区块的独立哈希 |
| `timestamp` | number | 区块创建时间戳（Unix 时间戳） |
| `last_retarget` | number | 上次难度调整时间戳 |
| `diff` | number/string | 当前挖矿难度（早期为数字，后期为大数字字符串） |
| `height` | number | 区块高度 |
| `hash` | string | 区块哈希 |
| `indep_hash` | string | 独立哈希（区块的唯一标识符） |
| `txs` | array | 区块中包含的交易 ID 列表 |
| `tx_root` | string | 交易树的根哈希（后期版本添加） |
| `tx_tree` | array | 交易树结构（后期版本添加） |
| `wallet_list` | string | 钱包列表的根哈希 |
| `reward_addr` | string | 挖矿奖励地址 |
| `tags` | array | 区块标签 |
| `reward_pool` | number/string | 奖励池余额 |
| `weave_size` | number/string | Weave 数据总大小（字节） |
| `block_size` | number/string | 区块大小（字节） |
| `cumulative_diff` | string | 累计难度（后期版本添加） |
| `hash_list_merkle` | string | 哈希列表的 Merkle 根 |
| `poa` | object | 访问证明（Proof of Access），包含 option、tx_path、data_path、chunk |
| `poa2` | object | 第二访问证明（最新版本添加） |
| `usd_to_ar_rate` | array | USD 到 AR 的汇率 [分子, 分母] |
| `scheduled_usd_to_ar_rate` | array | 计划的 USD 到 AR 汇率 |
| `price_per_gib_minute` | string | 每 GiB 每分钟的价格（最新版本添加） |
| `scheduled_price_per_gib_minute` | string | 计划的每 GiB 每分钟价格 |
| `packing_2_5_threshold` | string | 打包 2.5 阈值 |
| `strict_data_split_threshold` | string | 严格数据分割阈值 |
| `hash_preimage` | string | 哈希原像（最新版本添加） |
| `recall_byte` | string | 召回字节（最新版本添加） |
| `reward` | string | 奖励金额（最新版本添加） |
| `previous_solution_hash` | string | 前一个解决方案哈希 |
| `partition_number` | number | 分区号 |
| `nonce_limiter_info` | object | 随机数限制器信息 |
| `signature` | string | 区块签名 |
| `reward_key` | string | 奖励密钥 |
| `reward_history_hash` | string | 奖励历史哈希 |
| `debt_supply` | string | 债务供应量 |
| `kryder_plus_rate_multiplier` | string | Kryder 加速率乘数 |
| `kryder_plus_rate_multiplier_latch` | string | Kryder 加速率乘数锁存器 |
| `denomination` | string | 面额 |
| `redenomination_height` | number | 重新计价高度 |
| `double_signing_proof` | object | 双重签名证明 |
| `previous_cumulative_diff` | string | 前一个累计难度 |

## 访问证明 (POA) 结构

```json
{
  "option": "1",
  "tx_path": "...",
  "data_path": "...",
  "chunk": "..."
}
```

| 字段 | 说明 |
|------|------|
| `option` | 访问证明选项 |
| `tx_path` | 交易路径（Merkle 路径证明） |
| `data_path` | 数据路径（Merkle 路径证明） |
| `chunk` | 数据块内容（Base64 编码） |

## 代码示例

### cURL

```bash
curl --request GET \
  --url 'https://arweave.net/info'
```

### JavaScript (Fetch)

```javascript
fetch("https://arweave.net/info")
  .then((response) => response.json())
  .then((data) => {
    console.log("Arweave network height is: " + data.height);
  })
  .catch((error) => {
    console.error(error);
  });
```

### Node.js (Request)

```javascript
let request = require("request");

let options = {
  method: "GET",
  url: "https://arweave.net/info",
};

request(options, function (error, response, body) {
  if (error) {
    console.error(error);
  }
  console.log("Arweave network height is: " + JSON.parse(body).height);
});
```

## 客户端库

Arweave 特定的封装和客户端正在开发中，以简化常见操作和 API 交互。目前已有以下语言的集成：

- **Go**: https://github.com/everFinance/goar
- **PHP**: 可用
- **Scala**: 可用（也可用于 Java 和 C#）
- **JavaScript/TypeScript/NodeJS**: 可用

## 注意事项

1. **数据类型变化**: 随着协议升级，某些字段从数字类型变为字符串类型（特别是大数字字段）
2. **字段添加**: 新版本区块会添加新字段，旧字段保持不变
3. **POA 结构**: 访问证明结构在后期版本中变得更加复杂
4. **端口**: 默认端口为 1984，但网关通常使用标准 HTTP/HTTPS 端口（80/443）
5. **winston 单位**: 所有金额字段使用 winston 单位（1 AR = 10^12 winston），且以字符串形式返回
6. **Base64URL 编码**: 交易 ID 和地址使用 Base64URL 编码（URL 安全的 Base64）
7. **HTTP Range 请求**: 网关支持 HTTP Range 请求，可用于按需获取大型数据的部分内容
8. **交易提交**: 提交交易时需要包含完整的交易结构，包括签名

## API 端点汇总

| 端点 | 方法 | 说明 |
|------|------|------|
| `/info` | GET | 获取网络信息 |
| `/tx/[id]` | GET | 获取完整交易记录 |
| `/tx/[id]/status` | GET | 获取交易确认状态 |
| `/tx/[id]/[field]` | GET | 获取交易特定字段 |
| `/tx/[id]/data.html` | GET | 获取交易数据（HTML 格式） |
| `/tx/[id]/offset` | GET | 获取交易偏移量和大小 |
| `/tx` | POST | 提交交易 |
| `/block/hash/[id]` | GET | 通过哈希获取区块 |
| `/block/height/[height]` | GET | 通过高度获取区块 |
| `/current_block` | GET | 获取当前区块 |
| `/wallet/[address]/balance` | GET | 获取钱包余额 |
| `/wallet/[address]/last_tx` | GET | 获取最后交易 ID |
| `/wallet/[address]/txs/[earliest_tx]` | GET | 获取钱包发起的交易列表 |
| `/wallet/[address]/deposits/[earliest_deposit]` | GET | 获取钱包接收的交易列表 |
| `/price/[byte_size]` | GET | 获取交易预估价格 |
| `/[transaction_id]` | GET | 直接获取交易数据 |
| `/raw/[transaction_id]` | GET | 获取交易原始数据 |
| `/chunk/[offset]` | GET | 获取指定偏移量的数据块 |
| `/peers` | GET | 获取对等节点列表 |
