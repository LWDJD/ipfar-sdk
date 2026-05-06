package bundle

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
)

var DefaultGateways = []string{
	"https://arweave.net",
	"https://ar-io.net",
	"https://gateway.irys.xyz",
}

const (
	ArweaveSignType  = 1
	ED25519SignType  = 2
	EthereumSignType = 3
	SolanaSignType   = 4
)

type SigMeta struct {
	SigLength int
	PubLength int
	SigName   string
}

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

type Tag struct {
	Name  string
	Value string
}

type DataItem struct {
	SignatureType int
	Signature     []byte
	Owner         []byte
	Target        []byte
	Anchor        []byte
	Tags          []Tag
	Data          []byte
	Id            []byte
	HasTarget     bool
	HasAnchor     bool
}

type Bundle struct {
	Items []DataItem
}

type BundleBuilder struct {
	items []DataItem
}

func NewBundleBuilder() *BundleBuilder {
	return &BundleBuilder{
		items: make([]DataItem, 0),
	}
}

func (b *BundleBuilder) AddItem(item DataItem) {
	b.items = append(b.items, item)
}

func (b *BundleBuilder) GetItems() []DataItem {
	return b.items
}

func (b *BundleBuilder) ItemCount() int {
	return len(b.items)
}

func (b *BundleBuilder) Clear() {
	b.items = make([]DataItem, 0)
}

func NewDataItem() DataItem {
	return DataItem{
		Tags: make([]Tag, 0),
	}
}

func (d *DataItem) SetSignatureType(sigType int) error {
	if _, ok := SigConfigMap[sigType]; !ok {
		return fmt.Errorf("unsupported signature type: %d", sigType)
	}
	d.SignatureType = sigType
	return nil
}

func (d *DataItem) SetOwner(owner []byte) {
	d.Owner = owner
}

func (d *DataItem) SetTarget(target []byte) {
	d.Target = target
	d.HasTarget = len(target) > 0
}

func (d *DataItem) SetAnchor(anchor []byte) {
	d.Anchor = anchor
	d.HasAnchor = len(anchor) > 0
}

func (d *DataItem) AddTag(name, value string) {
	d.Tags = append(d.Tags, Tag{Name: name, Value: value})
}

func (d *DataItem) SetTags(tags []Tag) {
	d.Tags = tags
}

func (d *DataItem) SetData(data []byte) {
	d.Data = data
}

func (d *DataItem) SignWithRSA(privateKey *rsa.PrivateKey) error {
	d.SignatureType = ArweaveSignType
	d.Owner = padToLength(publicKeyBytes(&privateKey.PublicKey), 512)

	signData, err := d.signData()
	if err != nil {
		return err
	}

	hashed := sha256.Sum256(signData)
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hashed[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		return fmt.Errorf("failed to sign: %v", err)
	}

	paddedSig := padToLength(signature, 512)
	d.Signature = paddedSig
	d.Id = computeId(paddedSig)

	return nil
}

func (d *DataItem) SignWithEd25519(privateKey ed25519.PrivateKey) error {
	d.SignatureType = ED25519SignType

	signData, err := d.signData()
	if err != nil {
		return err
	}

	signature := ed25519.Sign(privateKey, signData)

	d.Signature = signature
	d.Owner = privateKey.Public().(ed25519.PublicKey)
	d.Id = computeId(signature)

	return nil
}

func (d *DataItem) signData() ([]byte, error) {
	if d.SignatureType == 0 {
		return nil, errors.New("signature type not set")
	}

	if len(d.Owner) == 0 {
		return nil, errors.New("owner not set")
	}

	tagsBytes, err := serializeTags(d.Tags)
	if err != nil {
		return nil, err
	}

	dataList := []interface{}{
		[]byte("dataitem"),
		[]byte("1"),
		[]byte(strconv.Itoa(d.SignatureType)),
		d.Owner,
		d.Target,
		d.Anchor,
		tagsBytes,
		d.Data,
	}

	hash := deepHash(dataList)
	return hash[:], nil
}

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

	if len(tags) == 0 {
		return append(result, encodeVInt(0)...), nil
	}

	blockSize := encodeVInt(int64(len(result)))
	avroArray := encodeVInt(-int64(len(tags)))
	avroArray = append(avroArray, blockSize...)
	avroArray = append(avroArray, result...)
	avroArray = append(avroArray, encodeVInt(0)...)

	return avroArray, nil
}

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

func publicKeyBytes(pubKey *rsa.PublicKey) []byte {
	return pubKey.N.Bytes()
}

func bytesTrimLeadingZeros(data []byte) []byte {
	i := 0
	for i < len(data) && data[i] == 0 {
		i++
	}
	if i == 0 {
		return data
	}
	result := make([]byte, len(data)-i)
	copy(result, data[i:])
	return result
}

func padToLength(data []byte, length int) []byte {
	if len(data) >= length {
		return data
	}
	padded := make([]byte, length)
	copy(padded[length-len(data):], data)
	return padded
}

func computeId(signature []byte) []byte {
	hash := sha256.Sum256(signature)
	return hash[:]
}

func (b *BundleBuilder) Build() ([]byte, error) {
	if len(b.items) == 0 {
		return nil, errors.New("bundle must contain at least one data item")
	}

	for i, item := range b.items {
		if len(item.Signature) == 0 {
			return nil, fmt.Errorf("item %d: signature not set", i)
		}
		if len(item.Owner) == 0 {
			return nil, fmt.Errorf("item %d: owner not set", i)
		}
		if len(item.Id) == 0 {
			return nil, fmt.Errorf("item %d: id not set", i)
		}
	}

	header := make([]byte, 0)

	itemsNum := int64(len(b.items))
	header = append(header, longToByteArray(itemsNum)...)

	for _, item := range b.items {
		encodedItem, err := encodeDataItem(item)
		if err != nil {
			return nil, err
		}

		itemBinaryLength := int64(len(encodedItem))
		header = append(header, longToByteArray(itemBinaryLength)...)
		header = append(header, item.Id...)
	}

	result := make([]byte, 0, len(header))
	result = append(result, header...)

	for _, item := range b.items {
		encodedItem, err := encodeDataItem(item)
		if err != nil {
			return nil, err
		}
		result = append(result, encodedItem...)
	}

	return result, nil
}

func (b *BundleBuilder) BuildToWriter(w io.Writer) error {
	data, err := b.Build()
	if err != nil {
		return err
	}

	_, err = w.Write(data)
	return err
}

func encodeDataItem(item DataItem) ([]byte, error) {
	if _, ok := SigConfigMap[item.SignatureType]; !ok {
		return nil, fmt.Errorf("unsupported signature type: %d", item.SignatureType)
	}

	result := make([]byte, 0)

	result = append(result, byte(item.SignatureType))
	result = append(result, byte(item.SignatureType>>8))

	result = append(result, item.Signature...)

	result = append(result, item.Owner...)

	if item.HasTarget {
		result = append(result, 1)
		result = append(result, item.Target...)
	} else {
		result = append(result, 0)
	}

	if item.HasAnchor {
		result = append(result, 1)
		result = append(result, item.Anchor...)
	} else {
		result = append(result, 0)
	}

	tagsBytes, err := serializeTags(item.Tags)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize tags: %v", err)
	}

	numOfTags := int64(len(item.Tags))
	result = append(result, longToByteArray(numOfTags)...)
	result = append(result, longToByteArray(int64(len(tagsBytes)))...)
	result = append(result, tagsBytes...)

	result = append(result, item.Data...)

	return result, nil
}

func longToByteArray(value int64) []byte {
	result := make([]byte, 32)
	for i := 0; i < 32; i++ {
		result[i] = byte(value >> (8 * i))
	}
	return result
}

func (d *DataItem) Verify() error {
	if len(d.Signature) == 0 {
		return errors.New("signature not set")
	}
	if len(d.Owner) == 0 {
		return errors.New("owner not set")
	}
	if len(d.Id) == 0 {
		return errors.New("id not set")
	}

	sigMeta, ok := SigConfigMap[d.SignatureType]
	if !ok {
		return fmt.Errorf("unsupported signature type: %d", d.SignatureType)
	}

	if len(d.Signature) != sigMeta.SigLength {
		return fmt.Errorf("invalid signature length: expected %d, got %d", sigMeta.SigLength, len(d.Signature))
	}

	if len(d.Owner) != sigMeta.PubLength {
		return fmt.Errorf("invalid owner length: expected %d, got %d", sigMeta.PubLength, len(d.Owner))
	}

	expectedId := computeId(d.Signature)
	if string(d.Id) != string(expectedId) {
		return fmt.Errorf("id mismatch: expected %x, got %x", expectedId, d.Id)
	}

	signData, err := d.signData()
	if err != nil {
		return fmt.Errorf("failed to compute sign data: %v", err)
	}

	switch d.SignatureType {
	case ArweaveSignType:
		ownerBytes := bytesTrimLeadingZeros(d.Owner)
		sigBytes := bytesTrimLeadingZeros(d.Signature)

		if len(ownerBytes) > 512 || len(ownerBytes) == 0 {
			return fmt.Errorf("invalid owner size after trim: %d bytes", len(ownerBytes))
		}
		if len(sigBytes) > 512 || len(sigBytes) == 0 {
			return fmt.Errorf("invalid signature size after trim: %d bytes", len(sigBytes))
		}

		pubKey := &rsa.PublicKey{
			N: new(big.Int).SetBytes(ownerBytes),
			E: 65537,
		}
		hashed := sha256.Sum256(signData)
		if err := rsa.VerifyPSS(pubKey, crypto.SHA256, hashed[:], sigBytes, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
			Hash:       crypto.SHA256,
		}); err != nil {
			return fmt.Errorf("signature verification failed: %v", err)
		}
	case ED25519SignType, SolanaSignType:
		if !ed25519.Verify(d.Owner, signData, d.Signature) {
			return errors.New("ed25519 signature verification failed")
		}
	default:
		return fmt.Errorf("signature type %d not supported for verification", d.SignatureType)
	}

	if len(d.Tags) > 128 {
		return fmt.Errorf("too many tags: %d (max 128)", len(d.Tags))
	}

	for i, tag := range d.Tags {
		if len(tag.Name) == 0 || len(tag.Value) == 0 {
			return fmt.Errorf("tag %d: name and value must be non-empty", i)
		}
		if len(tag.Name) > 1024 {
			return fmt.Errorf("tag %d: name too long (%d bytes, max 1024)", i, len(tag.Name))
		}
		if len(tag.Value) > 3072 {
			return fmt.Errorf("tag %d: value too long (%d bytes, max 3072)", i, len(tag.Value))
		}
	}

	if d.HasAnchor && len(d.Anchor) > 32 {
		return fmt.Errorf("anchor too long: %d bytes (max 32)", len(d.Anchor))
	}

	return nil
}

func (b *BundleBuilder) VerifyAll() error {
	for i, item := range b.items {
		if err := item.Verify(); err != nil {
			return fmt.Errorf("item %d verification failed: %v", i, err)
		}
	}
	return nil
}

func ParseBundle(data []byte) (*Bundle, error) {
	if len(data) < 32 {
		return nil, errors.New("data too short")
	}

	itemsNum := byteArrayToLong(data[:32])
	if itemsNum == 0 {
		return nil, errors.New("bundle must contain at least one item")
	}

	headerSize := 32 + int(itemsNum)*64
	if len(data) < headerSize {
		return nil, errors.New("header incomplete")
	}

	bundle := &Bundle{
		Items: make([]DataItem, 0, itemsNum),
	}

	currentOffset := headerSize

	for i := int64(0); i < itemsNum; i++ {
		itemMetaOffset := 32 + i*64
		itemBinaryLength := byteArrayToLong(data[itemMetaOffset : itemMetaOffset+32])
		itemId := data[itemMetaOffset+32 : itemMetaOffset+64]

		if currentOffset+int(itemBinaryLength) > len(data) {
			return nil, fmt.Errorf("item %d: data incomplete", i)
		}

		itemData := data[currentOffset : currentOffset+int(itemBinaryLength)]

		item, err := parseDataItem(itemData)
		if err != nil {
			return nil, fmt.Errorf("item %d: parse failed: %v", i, err)
		}

		if string(item.Id) != string(itemId) {
			return nil, fmt.Errorf("item %d: id mismatch", i)
		}

		bundle.Items = append(bundle.Items, item)
		currentOffset += int(itemBinaryLength)
	}

	return bundle, nil
}

func parseDataItem(data []byte) (DataItem, error) {
	if len(data) < 2 {
		return DataItem{}, errors.New("data too short")
	}

	sigType := int(data[0]) | int(data[1])<<8
	sigMeta, ok := SigConfigMap[sigType]
	if !ok {
		return DataItem{}, fmt.Errorf("unsupported signature type: %d", sigType)
	}

	pos := 2
	if len(data) < pos+sigMeta.SigLength {
		return DataItem{}, errors.New("signature incomplete")
	}

	signature := data[pos : pos+sigMeta.SigLength]
	pos += sigMeta.SigLength

	if len(data) < pos+sigMeta.PubLength {
		return DataItem{}, errors.New("owner incomplete")
	}

	owner := data[pos : pos+sigMeta.PubLength]
	pos += sigMeta.PubLength

	var target []byte
	hasTarget := false
	if pos >= len(data) {
		return DataItem{}, errors.New("target present byte missing")
	}
	targetPresent := data[pos] == 1
	pos++

	if targetPresent {
		if len(data) < pos+32 {
			return DataItem{}, errors.New("target incomplete")
		}
		target = data[pos : pos+32]
		pos += 32
		hasTarget = true
	}

	var anchor []byte
	hasAnchor := false
	if pos >= len(data) {
		return DataItem{}, errors.New("anchor present byte missing")
	}
	anchorPresent := data[pos] == 1
	pos++

	if anchorPresent {
		if len(data) < pos+32 {
			return DataItem{}, errors.New("anchor incomplete")
		}
		anchor = data[pos : pos+32]
		pos += 32
		hasAnchor = true
	}

	if pos+64 > len(data) {
		return DataItem{}, errors.New("tag metadata incomplete")
	}

	pos += 32
	tagsBytesLength := byteArrayToLong(data[pos:])
	pos += 32

	if pos+int(tagsBytesLength) > len(data) {
		return DataItem{}, errors.New("tags data incomplete")
	}

	tagsBytes := data[pos : pos+int(tagsBytesLength)]
	pos += int(tagsBytesLength)

	tags, err := deserializeTags(tagsBytes)
	if err != nil {
		return DataItem{}, fmt.Errorf("failed to deserialize tags: %v", err)
	}

	itemData := data[pos:]

	id := computeId(signature)

	return DataItem{
		SignatureType: sigType,
		Signature:     signature,
		Owner:         owner,
		Target:        target,
		Anchor:        anchor,
		Tags:          tags,
		Data:          itemData,
		Id:            id,
		HasTarget:     hasTarget,
		HasAnchor:     hasAnchor,
	}, nil
}

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
		count = -count
	}

	for count > 0 {
		for i := int64(0); i < count; i++ {
			nameSize, n, err := decodeVIntFromBytes(tagsBytes, pos)
			if err != nil {
				return tags, err
			}
			pos += n

			if pos+int(nameSize) > len(tagsBytes) {
				return tags, errors.New("tag name incomplete")
			}

			name := string(tagsBytes[pos : pos+int(nameSize)])
			pos += int(nameSize)

			valueSize, n, err := decodeVIntFromBytes(tagsBytes, pos)
			if err != nil {
				return tags, err
			}
			pos += n

			if pos+int(valueSize) > len(tagsBytes) {
				return tags, errors.New("tag value incomplete")
			}

			value := string(tagsBytes[pos : pos+int(valueSize)])
			pos += int(valueSize)

			tags = append(tags, Tag{Name: name, Value: value})
		}

		if pos >= len(tagsBytes) {
			break
		}

		count, n, err = decodeVIntFromBytes(tagsBytes, pos)
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
	}

	return tags, nil
}

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

func byteArrayToLong(data []byte) int64 {
	var result int64
	for i := 0; i < len(data) && i < 8; i++ {
		result |= int64(data[i]) << (8 * i)
	}
	return result
}
