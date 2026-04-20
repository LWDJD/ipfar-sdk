// Package arweave 提供 Arweave ANS-104 捆绑包的解析和验证功能
// 支持从本地文件或远程网关按需获取数据，实现轻量级验证
package arweave

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strconv"
)

// DefaultGateways 默认的 Arweave 网关列表，用于容错和负载均衡
var DefaultGateways = []string{
	"https://arweave.net",
	"https://ar-io.net",
	"https://gateway.irys.xyz",
}

// 签名类型常量，定义 ANS-104 支持的签名算法
const (
	ArweaveSignType  = 1 // Arweave 原生 RSA 签名
	ED25519SignType  = 2 // Ed25519 签名
	EthereumSignType = 3 // 以太坊 ECDSA 签名
	SolanaSignType   = 4 // Solana Ed25519 签名
)

// SigMeta 签名元数据，定义不同签名类型的参数
type SigMeta struct {
	SigLength int    // 签名长度（字节）
	PubLength int    // 公钥长度（字节）
	SigName   string // 签名算法名称
}

// SigConfigMap 签名类型配置映射表，用于快速查找签名参数
var SigConfigMap = map[int]SigMeta{
	ArweaveSignType: {
		SigLength: 512,
		PubLength: 512,
		SigName:   "arweave",
	},
	ED25519SignType: {
		SigLength: 64,
		PubLength: 32,
		SigName:   "ed25519",
	},
	EthereumSignType: {
		SigLength: 65,
		PubLength: 65,
		SigName:   "ethereum",
	},
	SolanaSignType: {
		SigLength: 64,
		PubLength: 32,
		SigName:   "solana",
	},
}

// Bundle 表示一个完整的 ANS-104 捆绑包
type Bundle struct {
	Items []BundleItem // 捆绑包中的所有数据项
}

// BundleItem 表示捆绑包中的单个数据项
type BundleItem struct {
	SignatureType int    // 签名类型（1=Arweave, 2=Ed25519, 3=Ethereum, 4=Solana）
	Signature     string // Base64 编码的签名
	Owner         string // Base64 编码的拥有者公钥
	Target        string // 可选的目标交易 ID
	Anchor        string // 可选的锚点值
	Tags          []Tag  // 标签数组
	Data          string // Base64 编码的数据内容
	Id            string // Base64 编码的数据项 ID（签名的 SHA-256 哈希）
}

// Tag 表示数据项的键值对标签
type Tag struct {
	Name  string // 标签名称
	Value string // 标签值
}

// BundleIndex 捆绑包索引，包含所有数据项的元信息
type BundleIndex struct {
	ItemsNum     int        // 数据项总数
	ItemsMeta    []ItemMeta // 每个数据项的元信息
	DataStartPos int        // 数据区的起始位置（字节偏移）
}

// ItemMeta 数据项元信息，用于快速定位和验证
type ItemMeta struct {
	Index         int    // 数据项索引
	Length        int    // 数据项二进制长度（字节）
	Id            string // Base64 编码的数据项 ID
	Offset        int    // 数据项在捆绑包中的字节偏移
	SignatureType int    // 签名类型
}

// BundleParser 捆绑包解析器，支持从 io.ReaderAt 接口读取数据
type BundleParser struct {
	reader io.ReaderAt  // 数据源读取接口
	index  *BundleIndex // 解析后的索引信息
}

// base64Encode 使用 Base64 URL 安全编码（无填充）将字节数组编码为字符串
func base64Encode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// base64Decode 使用 Base64 URL 安全编码（无填充）将字符串解码为字节数组
func base64Decode(data string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(data)
}

// decodeVInt 从字节流中解码 ZigZag 编码的变长整数（VInt）
// 使用 Apache Avro 规范的 ZigZag 编码，支持负数
// 参数 reader: 字节读取器
// 返回: 解码后的整数值和可能的错误
func decodeVInt(reader io.ByteReader) (int64, error) {
	var zigzag uint64
	var shift uint
	for {
		b, err := reader.ReadByte()
		if err != nil {
			return 0, err
		}
		zigzag |= uint64(b&0x7f) << shift
		shift += 7
		if b&0x80 == 0 {
			break
		}
	}

	if zigzag&1 != 0 {
		return ^int64(zigzag >> 1), nil
	}
	return int64(zigzag >> 1), nil
}

// decodeVIntFromBytes 从字节数组的指定位置解码 ZigZag 编码的 VInt
// 参数 data: 字节数组，offset: 起始偏移量
// 返回: 解码值、消耗的字节数、错误
func decodeVIntFromBytes(data []byte, offset int) (int64, int, error) {
	var zigzag uint64
	var shift uint
	pos := offset
	for pos < len(data) {
		b := data[pos]
		zigzag |= uint64(b&0x7f) << shift
		shift += 7
		pos++
		if b&0x80 == 0 {
			break
		}
	}

	if zigzag&1 != 0 {
		return ^int64(zigzag >> 1), pos - offset, nil
	}
	return int64(zigzag >> 1), pos - offset, nil
}

// decodeZigZagVIntFromBytes 从字节数组解码无符号 VInt（用于 Avro 数组计数）
// 与 decodeVIntFromBytes 不同，此函数不解码 ZigZag，直接返回原始值
// 参数 data: 字节数组，offset: 起始偏移量
// 返回: 解码值、消耗的字节数、错误
func decodeZigZagVIntFromBytes(data []byte, offset int) (int64, int, error) {
	var value uint64
	var shift uint
	pos := offset
	for pos < len(data) {
		b := data[pos]
		value |= uint64(b&0x7f) << shift
		shift += 7
		pos++
		if b&0x80 == 0 {
			break
		}
	}

	return int64(value), pos - offset, nil
}

// ownerToPubKey 将 Base64 编码的拥有者字符串转换为 RSA 公钥
// 用于 Arweave 签名验证
func ownerToPubKey(owner string) (*rsa.PublicKey, error) {
	by, err := base64Decode(owner)
	if err != nil {
		return nil, err
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(by),
		E: 65537,
	}, nil
}

// verifyRSA 验证 RSA PSS 签名
// 参数 msg: 原始消息，pubKey: RSA 公钥，sign: 签名数据
func verifyRSA(msg []byte, pubKey *rsa.PublicKey, sign []byte) error {
	hashed := sha256.Sum256(msg)
	return rsa.VerifyPSS(pubKey, crypto.SHA256, hashed[:], sign, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	})
}

// bundleItemSignData 计算数据项的签名数据（deep hash）
// 根据 ANS-104 规范，将数据项的各个字段按特定顺序进行深度哈希
func bundleItemSignData(d BundleItem) ([]byte, error) {
	tagsBytes, err := serializeTags(d.Tags)
	if err != nil {
		return nil, err
	}
	tagsBy := base64Encode(tagsBytes)

	dataList := []interface{}{
		base64Encode([]byte("dataitem")),
		base64Encode([]byte("1")),
		base64Encode([]byte(strconv.Itoa(d.SignatureType))),
		d.Owner,
		d.Target,
		d.Anchor,
		tagsBy,
		d.Data,
	}

	hash := deepHash(dataList)
	return hash[:], nil
}

// serializeTags 将标签数组序列化为 Avro 编码的字节数组
// 格式：[-1, 块大小, 标签数据..., 0]
// -1 表示带有大小前缀的 Avro 数组块，0 表示数组结束
func serializeTags(tags []Tag) ([]byte, error) {
	result := make([]byte, 0)
	for _, tag := range tags {
		nameBytes := []byte(tag.Name)
		valueBytes := []byte(tag.Value)
		result = append(result, encodeVInt(int64(len(nameBytes)))...)
		result = append(result, nameBytes...)
		result = append(result, encodeVInt(int64(len(valueBytes)))...)
		result = append(result, valueBytes...)
	}

	blockSize := encodeVInt(int64(len(result)))
	avroArray := encodeVInt(-1)
	avroArray = append(avroArray, blockSize...)
	avroArray = append(avroArray, result...)
	avroArray = append(avroArray, encodeVInt(0)...)

	return avroArray, nil
}

// encodeVInt 将整数编码为 ZigZag VInt 格式
// 使用 Apache Avro 规范的 ZigZag 编码，将负数映射为正数
func encodeVInt(value int64) []byte {
	var zigzag uint64
	if value < 0 {
		zigzag = uint64(^value<<1) | 1
	} else {
		zigzag = uint64(value << 1)
	}

	var result []byte
	for zigzag > 0x7f {
		result = append(result, byte(zigzag&0x7f)|0x80)
		zigzag >>= 7
	}
	result = append(result, byte(zigzag))
	return result
}

// deepHash 计算数据列表的深度哈希值
// 对每个元素依次进行 SHA-256 哈希，最终返回累积哈希
func deepHash(dataList []interface{}) [32]byte {
	hash := sha256.Sum256([]byte{})
	for _, data := range dataList {
		switch v := data.(type) {
		case string:
			hash = sha256.Sum256(append(hash[:], []byte(v)...))
		case []byte:
			hash = sha256.Sum256(append(hash[:], v...))
		}
	}
	return hash
}

// NewBundleParser 创建新的捆绑包解析器
// 参数 reader: 实现 io.ReaderAt 接口的数据源
func NewBundleParser(reader io.ReaderAt) *BundleParser {
	return &BundleParser{
		reader: reader,
	}
}

// ParseHeader 解析捆绑包头部，读取数据项数量和索引信息
// ANS-104 头部格式：
// - 前 32 字节：数据项数量（小端序）
// - 接下来 N*64 字节：每个数据项的元信息（32 字节长度 + 32 字节 ID）
func (p *BundleParser) ParseHeader() error {
	itemsNumBy := make([]byte, 32)
	n, err := p.reader.ReadAt(itemsNumBy, 0)
	if n < 32 || err != nil && err != io.EOF {
		return errors.New("binary length must more than 32")
	}

	itemsNum := byteArrayToLong(itemsNumBy)
	if itemsNum == 0 {
		return errors.New("bundle must contain at least one item")
	}

	index := &BundleIndex{
		ItemsNum:     itemsNum,
		DataStartPos: 32 + itemsNum*64,
		ItemsMeta:    make([]ItemMeta, 0, itemsNum),
	}

	currentOffset := 32 + itemsNum*64
	for i := 0; i < itemsNum; i++ {
		headerBegin := 32 + i*64
		headerByte := make([]byte, 64)
		n, err = p.reader.ReadAt(headerByte, int64(headerBegin))
		if n < 64 || err != nil && err != io.EOF {
			return errors.New("binary length incorrect")
		}

		itemBinaryLength := byteArrayToLong(headerByte[:32])
		id := base64Encode(headerByte[32:64])

		if itemBinaryLength < 0 {
			return fmt.Errorf("invalid item binary length at index %d", i)
		}

		index.ItemsMeta = append(index.ItemsMeta, ItemMeta{
			Index:  i,
			Length: itemBinaryLength,
			Id:     id,
			Offset: currentOffset,
		})

		currentOffset += itemBinaryLength
	}

	p.index = index
	return nil
}

// GetIndex 返回已解析的捆绑包索引
func (p *BundleParser) GetIndex() *BundleIndex {
	return p.index
}

// VerifyHeader 验证捆绑包头部的合法性
// 检查每个数据项的签名类型和长度是否有效
func (p *BundleParser) VerifyHeader() error {
	if p.index == nil {
		return errors.New("header not parsed, call ParseHeader first")
	}

	for _, meta := range p.index.ItemsMeta {
		if meta.Length < 2 {
			return fmt.Errorf("item %d: itemBinary too short", meta.Index)
		}

		sigTypeBy := make([]byte, 2)
		n, err := p.reader.ReadAt(sigTypeBy, int64(meta.Offset))
		if n < 2 || err != nil && err != io.EOF {
			return fmt.Errorf("item %d: cannot read signature type", meta.Index)
		}

		sigType := byteArrayToLong(sigTypeBy)
		sigMeta, ok := SigConfigMap[sigType]
		if !ok {
			return fmt.Errorf("item %d: unsupported sigType %d", meta.Index, sigType)
		}

		if meta.Length < 2+sigMeta.SigLength+sigMeta.PubLength {
			return fmt.Errorf("item %d: itemBinary too short for signature and owner", meta.Index)
		}
	}

	return nil
}

// FetchItem 从数据源中获取指定索引的数据项
// 参数 itemIndex: 数据项索引
// 返回: 解码后的 BundleItem 和可能的错误
func (p *BundleParser) FetchItem(itemIndex int) (BundleItem, error) {
	if p.index == nil {
		return BundleItem{}, errors.New("header not parsed, call ParseHeader first")
	}

	if itemIndex < 0 || itemIndex >= len(p.index.ItemsMeta) {
		return BundleItem{}, fmt.Errorf("item index %d out of range", itemIndex)
	}

	meta := p.index.ItemsMeta[itemIndex]
	itemBinary := make([]byte, meta.Length)
	n, err := p.reader.ReadAt(itemBinary, int64(meta.Offset))
	if n < meta.Length || err != nil && err != io.EOF {
		return BundleItem{}, fmt.Errorf("item %d: cannot read item data", itemIndex)
	}

	item, err := decodeBundleItem(itemBinary)
	if err != nil {
		return BundleItem{}, fmt.Errorf("item %d: decode failed: %v", itemIndex, err)
	}

	if item.Id != meta.Id {
		return BundleItem{}, fmt.Errorf("item %d: id mismatch, expected %s, got %s", itemIndex, meta.Id, item.Id)
	}

	return item, nil
}

// VerifyItem 验证指定数据项的签名和 ID
// 参数 itemIndex: 数据项索引
func (p *BundleParser) VerifyItem(itemIndex int) error {
	item, err := p.FetchItem(itemIndex)
	if err != nil {
		return err
	}

	return verifyBundleItem(item)
}

// FetchItemTags 仅获取指定数据项的标签，不下载完整数据
// 使用 HTTP Range 请求按需获取数据，节省带宽
// 参数 itemIndex: 数据项索引
// 返回: 标签数组和可能的错误
func (p *BundleParser) FetchItemTags(itemIndex int) ([]Tag, error) {
	if p.index == nil {
		return nil, errors.New("header not parsed, call ParseHeader first")
	}

	if itemIndex < 0 || itemIndex >= len(p.index.ItemsMeta) {
		return nil, fmt.Errorf("item index %d out of range", itemIndex)
	}

	meta := p.index.ItemsMeta[itemIndex]
	if meta.Length < 2 {
		return nil, fmt.Errorf("item %d: itemBinary too short", itemIndex)
	}

	sigTypeBy := make([]byte, 2)
	n, err := p.reader.ReadAt(sigTypeBy, int64(meta.Offset))
	if n < 2 || err != nil && err != io.EOF {
		return nil, fmt.Errorf("item %d: cannot read signature type", itemIndex)
	}

	sigType := byteArrayToLong(sigTypeBy)
	sigMeta, ok := SigConfigMap[sigType]
	if !ok {
		return nil, fmt.Errorf("item %d: unsupported sigType %d", itemIndex, sigType)
	}

	sigLength := sigMeta.SigLength
	ownerLength := sigMeta.PubLength
	position := 2 + sigLength + ownerLength

	tagsStart := position + 2
	anchorPresentBytePos := position + 1

	targetPresentByte := make([]byte, 1)
	n, err = p.reader.ReadAt(targetPresentByte, int64(meta.Offset+position))
	if n < 1 || err != nil && err != io.EOF {
		return nil, fmt.Errorf("item %d: cannot read target present byte", itemIndex)
	}

	if targetPresentByte[0] == 1 {
		tagsStart += 32
		anchorPresentBytePos += 32
	}

	anchorPresentByte := make([]byte, 1)
	n, err = p.reader.ReadAt(anchorPresentByte, int64(meta.Offset+anchorPresentBytePos))
	if n < 1 || err != nil && err != io.EOF {
		return nil, fmt.Errorf("item %d: cannot read anchor present byte", itemIndex)
	}

	if anchorPresentByte[0] == 1 {
		tagsStart += 32
	}

	numOfTagsBy := make([]byte, 8)
	n, err = p.reader.ReadAt(numOfTagsBy, int64(meta.Offset+tagsStart))
	if n < 8 || err != nil && err != io.EOF {
		return nil, fmt.Errorf("item %d: cannot read num of tags", itemIndex)
	}

	numOfTags := byteArrayToLong(numOfTagsBy)

	if numOfTags == 0 {
		return []Tag{}, nil
	}

	tagsBytesLengthBy := make([]byte, 8)
	n, err = p.reader.ReadAt(tagsBytesLengthBy, int64(meta.Offset+tagsStart+8))
	if n < 8 || err != nil && err != io.EOF {
		return nil, fmt.Errorf("item %d: cannot read tags bytes length", itemIndex)
	}

	tagsBytesLength := byteArrayToLong(tagsBytesLengthBy)

	tagsBytes := make([]byte, tagsBytesLength)
	n, err = p.reader.ReadAt(tagsBytes, int64(meta.Offset+tagsStart+16))
	if n < int(tagsBytesLength) || err != nil && err != io.EOF {
		return nil, fmt.Errorf("item %d: cannot read tags bytes", itemIndex)
	}

	tags, err := deserializeTags(tagsBytes)
	if err != nil {
		return nil, fmt.Errorf("item %d: failed to deserialize tags: %v", itemIndex, err)
	}
	return tags, nil
}

// ParseAll 解析并获取完整的捆绑包数据
// 自动解析头部（如果尚未解析），然后获取所有数据项
func (p *BundleParser) ParseAll() (Bundle, error) {
	if p.index == nil {
		if err := p.ParseHeader(); err != nil {
			return Bundle{}, err
		}
	}

	bundle := Bundle{
		Items: make([]BundleItem, 0, p.index.ItemsNum),
	}

	for i := 0; i < p.index.ItemsNum; i++ {
		item, err := p.FetchItem(i)
		if err != nil {
			return Bundle{}, err
		}
		bundle.Items = append(bundle.Items, item)
	}

	return bundle, nil
}

// VerifyAll 验证捆绑包中的所有数据项
// 自动解析头部（如果尚未解析），然后验证每个数据项的签名
func (p *BundleParser) VerifyAll() error {
	if p.index == nil {
		if err := p.ParseHeader(); err != nil {
			return err
		}
	}

	for i := 0; i < p.index.ItemsNum; i++ {
		if err := p.VerifyItem(i); err != nil {
			return fmt.Errorf("item %d verification failed: %v", i, err)
		}
	}

	return nil
}

// decodeBundleItem 将二进制数据解码为 BundleItem 结构
// 根据 ANS-104 规范解析数据项的各个字段
// 参数 itemBinary: 数据项的原始二进制数据
// 返回: 解码后的 BundleItem 和可能的错误
func decodeBundleItem(itemBinary []byte) (BundleItem, error) {
	if len(itemBinary) < 2 {
		return BundleItem{}, errors.New("itemBinary incorrect")
	}

	sigType := byteArrayToLong(itemBinary[:2])
	sigMeta, ok := SigConfigMap[sigType]
	if !ok {
		return BundleItem{}, fmt.Errorf("not support sigType:%d", sigType)
	}

	sigLength := sigMeta.SigLength
	if len(itemBinary) < sigLength+2 {
		return BundleItem{}, errors.New("itemBinary incorrect")
	}

	sigBy := itemBinary[2 : sigLength+2]
	signature := base64Encode(sigBy)
	idhash := sha256.Sum256(sigBy)
	id := base64Encode(idhash[:])

	ownerLength := sigMeta.PubLength
	if len(itemBinary) < sigLength+2+ownerLength {
		return BundleItem{}, errors.New("itemBinary incorrect")
	}

	owner := base64Encode(itemBinary[sigLength+2 : sigLength+2+ownerLength])

	target := ""
	anchor := ""
	position := 2 + sigLength + ownerLength
	tagsStart := position + 2
	anchorPresentByte := position + 1

	if len(itemBinary) < position {
		return BundleItem{}, errors.New("itemBinary incorrect")
	}

	targetPresent := itemBinary[position] == 1
	if targetPresent {
		tagsStart += 32
		anchorPresentByte += 32
		if len(itemBinary) < position+1+32 {
			return BundleItem{}, errors.New("itemBinary incorrect")
		}
		target = base64Encode(itemBinary[position+1 : position+1+32])
	}

	if len(itemBinary) < anchorPresentByte {
		return BundleItem{}, errors.New("itemBinary incorrect")
	}

	anchorPresent := itemBinary[anchorPresentByte] == 1
	if anchorPresent {
		tagsStart += 32
		if len(itemBinary) < anchorPresentByte+1+32 {
			return BundleItem{}, errors.New("itemBinary incorrect")
		}
		anchor = base64Encode(itemBinary[anchorPresentByte+1 : anchorPresentByte+1+32])
	}

	numOfTags := byteArrayToLong(itemBinary[tagsStart : tagsStart+8])

	var tagsBytesLength int
	var tags []Tag
	if numOfTags > 0 {
		if len(itemBinary) < tagsStart+16 {
			return BundleItem{}, errors.New("itemBinary incorrect")
		}
		tagsBytesLength = byteArrayToLong(itemBinary[tagsStart+8 : tagsStart+16])
		if len(itemBinary) < tagsStart+16+tagsBytesLength || tagsStart+16+tagsBytesLength < 0 {
			return BundleItem{}, errors.New("itemBinary incorrect")
		}
		tagsBytes := itemBinary[tagsStart+16 : tagsStart+16+tagsBytesLength]
		var err error
		tags, err = deserializeTags(tagsBytes)
		if err != nil {
			return BundleItem{}, fmt.Errorf("failed to deserialize tags: %v", err)
		}
	}

	data := itemBinary[tagsStart+16+tagsBytesLength:]

	return BundleItem{
		SignatureType: sigType,
		Signature:     signature,
		Owner:         owner,
		Target:        target,
		Anchor:        anchor,
		Tags:          tags,
		Data:          base64Encode(data),
		Id:            id,
	}, nil
}

// deserializeTags 将 Avro 编码的标签字节数组解码为 Tag 数组
// 参数 tagsBytes: Avro 编码的标签数据
// 返回: 解码后的标签数组和可能的错误
func deserializeTags(tagsBytes []byte) ([]Tag, error) {
	tags := []Tag{}
	pos := 0

	count, n, err := decodeVIntFromBytes(tagsBytes, pos)
	if err != nil {
		return tags, err
	}
	pos += n

	if count < 0 {
		size, n, err := decodeVIntFromBytes(tagsBytes, pos)
		if err != nil {
			return tags, err
		}
		pos += n
		_ = size
	}

	for count > 0 {
		if pos >= len(tagsBytes) {
			break
		}

		nameLen, n, err := decodeVIntFromBytes(tagsBytes, pos)
		if err != nil {
			return tags, err
		}
		pos += n

		if pos+int(nameLen) > len(tagsBytes) {
			break
		}
		name := string(tagsBytes[pos : pos+int(nameLen)])
		pos += int(nameLen)

		valueLen, n, err := decodeVIntFromBytes(tagsBytes, pos)
		if err != nil {
			return tags, err
		}
		pos += n

		if pos+int(valueLen) > len(tagsBytes) {
			break
		}
		value := string(tagsBytes[pos : pos+int(valueLen)])
		pos += int(valueLen)

		tags = append(tags, Tag{Name: name, Value: value})
		count--
	}

	return tags, nil
}

// verifyBundleItem 验证单个数据项的签名和 ID
// 检查 ID 是否与签名匹配，签名是否与公钥匹配
func verifyBundleItem(d BundleItem) error {
	signMsg, err := bundleItemSignData(d)
	if err != nil {
		return fmt.Errorf("failed to get signature data: %v", err)
	}

	sign, err := base64Decode(d.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %v", err)
	}

	idBytes := sha256.Sum256(sign)
	id := base64Encode(idBytes[:])
	if id != d.Id {
		return fmt.Errorf("verify Id is not equal; id: %s, recId: %s", d.Id, id)
	}

	switch d.SignatureType {
	case ArweaveSignType:
		pubKey, err := ownerToPubKey(d.Owner)
		if err != nil {
			return fmt.Errorf("failed to convert owner to public key: %v", err)
		}
		return verifyRSA(signMsg, pubKey, sign)

	case ED25519SignType, SolanaSignType:
		pubkey, err := base64Decode(d.Owner)
		if err != nil {
			return err
		}
		if !ed25519.Verify(pubkey, signMsg, sign) {
			return errors.New("verify ed25519 signature failed")
		}
		return nil

	case EthereumSignType:
		return errors.New("ethereum signature verification not implemented")

	default:
		return errors.New("not support the signType")
	}
}

// byteArrayToLong 将字节数组转换为整数（小端序）
// 用于解析 ANS-104 头部中的长度和数量字段
func byteArrayToLong(b []byte) int {
	value := 0
	for i := len(b) - 1; i >= 0; i-- {
		value = value*256 + int(b[i])
	}
	return value
}

// byteArrayToLongBE 将字节数组转换为整数（大端序）
// 目前未使用，保留以备将来需要
func byteArrayToLongBE(b []byte) int {
	value := 0
	for i := 0; i < len(b); i++ {
		value = value*256 + int(b[i])
	}
	return value
}

// ParseBundleFromFile 从本地文件创建捆绑包解析器
// 参数 filePath: 文件路径
// 返回: 解析器和可能的错误
func ParseBundleFromFile(filePath string) (*BundleParser, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}

	parser := NewBundleParser(file)
	if err := parser.ParseHeader(); err != nil {
		file.Close()
		return nil, err
	}

	return parser, nil
}

// HTTPRangeReader 实现 io.ReaderAt 接口，支持通过 HTTP Range 请求读取远程数据
// 用于按需获取捆绑包数据，避免下载整个文件
type HTTPRangeReader struct {
	url    string       // 数据 URL
	client *http.Client // HTTP 客户端
	length int64        // 数据总长度（-1 表示未知）
}

// NewHTTPRangeReader 创建新的 HTTP Range 读取器
func NewHTTPRangeReader(url string) *HTTPRangeReader {
	return &HTTPRangeReader{
		url:    url,
		client: &http.Client{},
		length: -1,
	}
}

// ReadAt 实现 io.ReaderAt 接口的 ReadAt 方法
// 通过 HTTP Range 请求读取指定偏移量的数据
func (r *HTTPRangeReader) ReadAt(p []byte, off int64) (n int, err error) {
	req, err := http.NewRequest("GET", r.url, nil)
	if err != nil {
		return 0, err
	}

	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", off, off+int64(len(p))-1))

	resp, err := r.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("HTTP status: %d", resp.StatusCode)
	}

	return io.ReadFull(resp.Body, p)
}

// ParseBundleHeaderFromURL 从 URL 解析捆绑包头部
// 使用多网关容错机制，依次尝试各个网关
// 参数 url: 捆绑包 URL
// 返回: 解析器和可能的错误
func ParseBundleHeaderFromURL(url string) (*BundleParser, error) {
	var lastErr error

	for _, gateway := range DefaultGateways {
		testURL := fmt.Sprintf("%s/raw/%s", gateway, extractTxIDFromURL(url))
		parser, err := tryParseBundleHeader(testURL)
		if err == nil {
			return parser, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("all gateways failed: %v", lastErr)
}

// tryParseBundleHeader 尝试从单个网关解析捆绑包头部
// 使用两次 HTTP Range 请求：
// 1. 第一次获取前 32 字节，读取数据项数量
// 2. 第二次获取完整头部（32 + N*64 字节）
func tryParseBundleHeader(url string) (*BundleParser, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Range", "bytes=0-31")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP status: %d", resp.StatusCode)
	}

	itemsNumBy := make([]byte, 32)
	_, err = io.ReadFull(resp.Body, itemsNumBy)
	resp.Body.Close()
	if err != nil {
		return nil, errors.New("failed to read items count")
	}

	itemsNum := byteArrayToLong(itemsNumBy)
	if itemsNum == 0 {
		return nil, errors.New("bundle must contain at least one item")
	}

	headerSize := 32 + itemsNum*64

	req2, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req2.Header.Set("Range", fmt.Sprintf("bytes=0-%d", headerSize-1))

	resp2, err := client.Do(req2)
	if err != nil {
		return nil, err
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusPartialContent && resp2.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status: %d", resp2.StatusCode)
	}

	headerData := make([]byte, headerSize)
	_, err = io.ReadFull(resp2.Body, headerData)
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %v", err)
	}

	reader := NewBytesReader(headerData)
	parser := NewBundleParser(reader)
	if err := parser.ParseHeader(); err != nil {
		return nil, err
	}

	parser.reader = NewHTTPRangeReader(url)
	return parser, nil
}

// extractTxIDFromURL 从 URL 中提取交易 ID
// 例如：https://arweave.net/raw/txID -> txID
func extractTxIDFromURL(url string) string {
	for i := len(url) - 1; i >= 0; i-- {
		if url[i] == '/' {
			return url[i+1:]
		}
	}
	return url
}

// BytesReader 实现 io.ReaderAt 接口的内存读取器
type BytesReader struct {
	data []byte // 字节数据
	pos  int    // 当前位置
}

// NewBytesReader 创建新的内存读取器
func NewBytesReader(data []byte) *BytesReader {
	return &BytesReader{data: data}
}

// ReadAt 实现 io.ReaderAt 接口的 ReadAt 方法
func (r *BytesReader) ReadAt(p []byte, off int64) (n int, err error) {
	if off >= int64(len(r.data)) {
		return 0, io.EOF
	}
	n = copy(p, r.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// ParseBundleItemFromURL 从 URL 获取指定索引的数据项
// 使用 HTTP Range 请求按需获取数据，避免下载整个捆绑包
// 参数 url: 捆绑包 URL，itemIndex: 数据项索引，parser: 已解析的头部
// 返回: 数据项和可能的错误
func ParseBundleItemFromURL(url string, itemIndex int, parser *BundleParser) (BundleItem, error) {
	if parser.index == nil {
		return BundleItem{}, errors.New("header not parsed")
	}

	if itemIndex < 0 || itemIndex >= len(parser.index.ItemsMeta) {
		return BundleItem{}, fmt.Errorf("item index %d out of range", itemIndex)
	}

	meta := parser.index.ItemsMeta[itemIndex]

	reader := NewHTTPRangeReader(url)
	itemBinary := make([]byte, meta.Length)
	n, err := reader.ReadAt(itemBinary, int64(meta.Offset))
	if n < meta.Length || err != nil && err != io.EOF {
		return BundleItem{}, fmt.Errorf("item %d: cannot read item data", itemIndex)
	}

	item, err := decodeBundleItem(itemBinary)
	if err != nil {
		return BundleItem{}, fmt.Errorf("item %d: decode failed: %v", itemIndex, err)
	}

	return item, nil
}

// FetchItemTagsFromURL 从 URL 获取指定数据项的标签
// 使用多网关容错和 HTTP Range 请求，仅获取必要数据
// 参数 url: 捆绑包 URL，itemIndex: 数据项索引，parser: 已解析的头部
// 返回: 标签数组和可能的错误
func FetchItemTagsFromURL(url string, itemIndex int, parser *BundleParser) ([]Tag, error) {
	if parser.index == nil {
		return nil, errors.New("header not parsed")
	}

	if itemIndex < 0 || itemIndex >= len(parser.index.ItemsMeta) {
		return nil, fmt.Errorf("item index %d out of range", itemIndex)
	}

	meta := parser.index.ItemsMeta[itemIndex]

	var lastErr error
	for _, gateway := range DefaultGateways {
		txID := extractTxIDFromURL(url)
		gatewayURL := fmt.Sprintf("%s/raw/%s", gateway, txID)
		tags, err := tryFetchItemTags(gatewayURL, itemIndex, meta)
		if err == nil {
			return tags, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("all gateways failed: %v", lastErr)
}

// tryFetchItemTags 尝试从单个网关获取数据项标签
// 使用 HTTP Range 请求仅获取标签相关数据，节省带宽
func tryFetchItemTags(url string, itemIndex int, meta ItemMeta) ([]Tag, error) {
	client := &http.Client{
		Timeout: 60000000000,
	}

	maxTagsFetch := 16384
	fetchSize := 2 + 512 + 512 + 1 + 1 + 16 + maxTagsFetch
	if fetchSize > meta.Length {
		fetchSize = meta.Length
	}

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", meta.Offset, meta.Offset+fetchSize-1))

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusPartialContent {
		itemData := make([]byte, fetchSize)
		n, err := io.ReadFull(resp.Body, itemData)
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("item %d: cannot read item data (%d bytes): %v", itemIndex, fetchSize, err)
		}

		if n < fetchSize {
			return nil, fmt.Errorf("item %d: incomplete read, got %d of %d bytes", itemIndex, n, fetchSize)
		}

		return parseTagsFromItemData(itemData, itemIndex, meta, client, url)
	}

	if resp.StatusCode == http.StatusOK {
		fullItemData := make([]byte, meta.Length)
		n, err := io.ReadFull(resp.Body, fullItemData)
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("item %d: cannot read full item data: %v", itemIndex, err)
		}

		if n < meta.Length {
			return nil, fmt.Errorf("item %d: incomplete read, got %d of %d bytes", itemIndex, n, meta.Length)
		}

		return parseTagsFromItemData(fullItemData, itemIndex, meta, client, url)
	}

	return nil, fmt.Errorf("HTTP status: %d", resp.StatusCode)
}

// parseTagsFromItemData 从数据项的二进制数据中解析标签
// 根据 ANS-104 规范解析签名类型、可选字段（target/anchor）和 Avro 编码的标签
// 如果初始数据不完整，会使用额外的 HTTP Range 请求获取缺失数据
func parseTagsFromItemData(itemData []byte, itemIndex int, meta ItemMeta, client *http.Client, url string) ([]Tag, error) {
	sigType := byteArrayToLong(itemData[0:2])
	sigMeta, ok := SigConfigMap[sigType]
	if !ok {
		return nil, fmt.Errorf("item %d: unsupported sigType %d", itemIndex, sigType)
	}

	position := 2 + sigMeta.SigLength + sigMeta.PubLength

	if position+1 > len(itemData) {
		return nil, fmt.Errorf("item %d: item data too short for target byte", itemIndex)
	}

	if itemData[position] == 1 {
		position += 32
	}

	if position+1 > len(itemData) {
		return nil, fmt.Errorf("item %d: item data too short for anchor byte", itemIndex)
	}

	if itemData[position] == 1 {
		position += 32
	}

	tagsStart := position

	var tags []Tag
	pos := tagsStart

	for pos < len(itemData) {
		count, vintSize, err := decodeZigZagVIntFromBytes(itemData, pos)
		if err != nil {
			return nil, fmt.Errorf("item %d: failed to decode tag count: %v", itemIndex, err)
		}
		pos += vintSize

		if count == 0 {
			break
		}

		if count < 0 {
			blockSize, sizeVintSize, err := decodeZigZagVIntFromBytes(itemData, pos)
			if err != nil {
				return nil, fmt.Errorf("item %d: failed to decode block size: %v", itemIndex, err)
			}
			pos += sizeVintSize
			count = -count

			blockEnd := pos + int(blockSize)
			if blockEnd > len(itemData) {
				remainingBytes := blockEnd - len(itemData)
				req2, _ := http.NewRequest("GET", url, nil)
				req2.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", meta.Offset+len(itemData), meta.Offset+blockEnd-1))
				resp2, err := client.Do(req2)
				if err != nil {
					return nil, err
				}
				defer resp2.Body.Close()

				if resp2.StatusCode != http.StatusPartialContent && resp2.StatusCode != http.StatusOK {
					return nil, fmt.Errorf("HTTP status: %d", resp2.StatusCode)
				}

				additionalData := make([]byte, remainingBytes)
				_, err = io.ReadFull(resp2.Body, additionalData)
				if err != nil && err != io.EOF {
					return nil, fmt.Errorf("item %d: cannot read additional data (%d bytes needed): %v", itemIndex, remainingBytes, err)
				}

				itemData = append(itemData, additionalData...)
			}
		}

		for i := int64(0); i < count; i++ {
			if pos >= len(itemData) {
				return nil, fmt.Errorf("item %d: unexpected end of data while parsing tag %d", itemIndex, len(tags))
			}

			nameSize, nameSizeLen, err := decodeZigZagVIntFromBytes(itemData, pos)
			if err != nil {
				return nil, fmt.Errorf("item %d: failed to decode tag name size: %v", itemIndex, err)
			}
			pos += nameSizeLen

			if pos+int(nameSize) > len(itemData) {
				return nil, fmt.Errorf("item %d: tag name extends beyond data", itemIndex)
			}

			tagName := string(itemData[pos : pos+int(nameSize)])
			pos += int(nameSize)

			valueSize, valueSizeLen, err := decodeZigZagVIntFromBytes(itemData, pos)
			if err != nil {
				return nil, fmt.Errorf("item %d: failed to decode tag value size: %v", itemIndex, err)
			}
			pos += valueSizeLen

			if pos+int(valueSize) > len(itemData) {
				return nil, fmt.Errorf("item %d: tag value extends beyond data", itemIndex)
			}

			tagValue := string(itemData[pos : pos+int(valueSize)])
			pos += int(valueSize)

			tags = append(tags, Tag{Name: tagName, Value: tagValue})
		}
	}

	return tags, nil
}
