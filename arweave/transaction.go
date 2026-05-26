package arweave

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
)

// Tag represents an Arweave transaction tag.  Name and Value are stored
// in their base64url-encoded form in JSON, matching the goar convention
// that real Arweave mainnet gateways expect.
type Tag struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Transaction represents an Arweave v2 transaction.  Tags are base64url-encoded
// both in JSON and in the deep hash computation (SHA-384).
type Transaction struct {
	Format    int    `json:"format"`
	ID        string `json:"id"`
	LastTx    string `json:"last_tx"`
	Owner     string `json:"owner"`
	Target    string `json:"target"`
	Quantity  string `json:"quantity"`
	Data      string `json:"data"`
	DataSize  string `json:"data_size"`
	DataRoot  string `json:"data_root"`
	Reward    string `json:"reward"`
	Signature string `json:"signature"`
	Tags      []Tag  `json:"tags"`
}

// TransactionBuilder incrementally builds a Transaction.
type TransactionBuilder struct {
	owner    string
	data     []byte
	tags     []Tag
	target   string
	quantity string
	reward   string
	lastTx   string
}

// NewTransactionBuilder creates a builder for the given owner.
func NewTransactionBuilder(owner string) *TransactionBuilder {
	return &TransactionBuilder{
		owner:    owner,
		quantity: "0",
		reward:   "0",
	}
}

// SetData sets the transaction data payload.
func (tb *TransactionBuilder) SetData(data []byte) { tb.data = data }

// SetTags replaces all tags.
func (tb *TransactionBuilder) SetTags(tags []Tag) { tb.tags = tags }

// AddTag appends a tag.  The tag values are stored as-is; they will be
// base64url-encoded when the transaction is serialized to JSON.
func (tb *TransactionBuilder) AddTag(name, value string) {
	tb.tags = append(tb.tags, Tag{Name: name, Value: value})
}

// SetTarget sets the optional target address.
func (tb *TransactionBuilder) SetTarget(target string) { tb.target = target }

// SetReward sets the mining reward.
func (tb *TransactionBuilder) SetReward(reward string) { tb.reward = reward }

// SetLastTx sets the anchor (last_tx).
func (tb *TransactionBuilder) SetLastTx(lastTx string) { tb.lastTx = lastTx }

// Build creates an unsigned Transaction.  Tags are stored in their
// original (plain-text) form inside the struct; the caller or ToJSON
// is responsible for base64-encoding them when producing JSON.
func (tb *TransactionBuilder) Build() *Transaction {
	dataRoot := ""
	if len(tb.data) > 0 {
		h := sha256.Sum256(tb.data)
		dataRoot = base64.RawURLEncoding.EncodeToString(h[:])
	}

	return &Transaction{
		Format:   2,
		Owner:    tb.owner,
		Target:   tb.target,
		Quantity: tb.quantity,
		Data:     base64.RawURLEncoding.EncodeToString(tb.data),
		DataSize: strconv.Itoa(len(tb.data)),
		DataRoot: dataRoot,
		Reward:   tb.reward,
		LastTx:   tb.lastTx,
		Tags:     tb.tags,
	}
}

// Sign signs the transaction using RSA-PSS SHA-256 over the SHA-384 deep hash
// (matching the Arweave v2 spec as implemented by goar).
func (tx *Transaction) Sign(privKey *rsa.PrivateKey) error {
	sigData, err := tx.signatureData()
	if err != nil {
		return fmt.Errorf("failed to compute signature data: %w", err)
	}

	hashed := sha256.Sum256(sigData)
	sig, err := rsa.SignPSS(rand.Reader, privKey, crypto.SHA256, hashed[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		return fmt.Errorf("failed to sign: %w", err)
	}

	tx.Signature = base64.RawURLEncoding.EncodeToString(sig)
	idHash := sha256.Sum256(sig)
	tx.ID = base64.RawURLEncoding.EncodeToString(idHash[:])
	return nil
}

// ToJSON serializes the transaction to JSON.  Tags are base64url-encoded
// in the output so that the resulting JSON matches what Arweave mainnet
// gateways expect (goar-compatible format).
func (tx *Transaction) ToJSON() ([]byte, error) {
	// Build a map with base64-encoded tags.
	encodedTags := make([]Tag, len(tx.Tags))
	for i, t := range tx.Tags {
		encodedTags[i] = Tag{
			Name:  base64.RawURLEncoding.EncodeToString([]byte(t.Name)),
			Value: base64.RawURLEncoding.EncodeToString([]byte(t.Value)),
		}
	}

	m := map[string]interface{}{
		"format":    tx.Format,
		"id":        tx.ID,
		"last_tx":   tx.LastTx,
		"owner":     tx.Owner,
		"target":    tx.Target,
		"quantity":  tx.Quantity,
		"data":      tx.Data,
		"data_size": tx.DataSize,
		"data_root": tx.DataRoot,
		"reward":    tx.Reward,
		"signature": tx.Signature,
		"tags":      encodedTags,
	}
	return json.Marshal(m)
}

// ToJSONRaw serializes the transaction to JSON without base64-encoding tags.
// This is useful for testing or when comparing with legacy (plain-text) formats.
func (tx *Transaction) ToJSONRaw() ([]byte, error) {
	return json.Marshal(tx)
}

// =============================================================================
// SHA-384 Deep Hash (goar-compatible)
// =============================================================================

// signatureData computes the deep hash of the transaction for signing,
// using SHA-384 as required by the Arweave v2 spec (goar convention).
func (tx *Transaction) signatureData() ([]byte, error) {
	// Build the data list in the exact order goar's GetSignatureData expects.
	// Each string value is base64url-encoded because deepHashStr will
	// base64-decode it before hashing (goar convention).
	dataList := []interface{}{
		base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(tx.Format))),
		tx.Owner,
		tx.Target,
		base64.RawURLEncoding.EncodeToString([]byte(tx.Quantity)),
		base64.RawURLEncoding.EncodeToString([]byte(tx.Reward)),
		tx.LastTx,
		tagsToSigData(tx.Tags), // [][]string with base64-encoded values
		base64.RawURLEncoding.EncodeToString([]byte(tx.DataSize)),
		tx.DataRoot,
	}

	hash := deepHashList(dataList)
	return hash[:], nil
}

// tagsToSigData converts tags to the [][]string format that goar's
// DeepHash expects.  Tag names and values are base64url-encoded.
func tagsToSigData(tags []Tag) [][]string {
	out := make([][]string, len(tags))
	for i, t := range tags {
		out[i] = []string{
			base64.RawURLEncoding.EncodeToString([]byte(t.Name)),
			base64.RawURLEncoding.EncodeToString([]byte(t.Value)),
		}
	}
	return out
}

// deepHashList is the goar-compatible DeepHash for a list of items.
// It mirrors goar's utils.DeepHash exactly.
func deepHashList(data []interface{}) [48]byte {
	tag := append([]byte("list"), []byte(strconv.Itoa(len(data)))...)
	tagHash := sha512.Sum384(tag)
	return deepHashChunk(data, tagHash)
}

// deepHashChunk recursively hashes each element, chaining with the accumulator.
func deepHashChunk(data []interface{}, acc [48]byte) [48]byte {
	if len(data) < 1 {
		return acc
	}

	var dHash [48]byte
	item := data[0]

	// If it's a string: treat as blob.
	if s, ok := item.(string); ok {
		dHash = deepHashStr(s)
	} else {
		// Reflect to handle slices (like [][]string for tags).
		v := reflect.ValueOf(item)
		if v.Kind() == reflect.Slice {
			sub := make([]interface{}, v.Len())
			for i := 0; i < v.Len(); i++ {
				sub[i] = v.Index(i).Interface()
			}
			dHash = deepHashList(sub)
		}
	}

	hashPair := append(acc[:], dHash[:]...)
	newAcc := sha512.Sum384(hashPair)
	return deepHashChunk(data[1:], newAcc)
}

// deepHashStr computes the deep hash of a base64url-encoded string.
// It mirrors goar's utils.deepHashStr.
func deepHashStr(str string) [48]byte {
	by, err := base64.RawURLEncoding.DecodeString(str)
	if err != nil {
		// Should never happen; fall back to treating as raw bytes.
		by = []byte(str)
	}
	tag := append([]byte("blob"), []byte(strconv.Itoa(len(by)))...)
	tagHash := sha512.Sum384(tag)
	blobHash := sha512.Sum384(by)
	tagged := append(tagHash[:], blobHash[:]...)
	return sha512.Sum384(tagged)
}

// =============================================================================
// Legacy helpers (used internally by chunked path)
// =============================================================================

// base64Encode is a package-level convenience wrapper.
func base64Encode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// base64Decode is a package-level convenience wrapper.
func base64Decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// concatBuffer concatenates byte slices efficiently.
func concatBuffer(buffers ...[]byte) []byte {
	total := 0
	for _, b := range buffers {
		total += len(b)
	}
	out := make([]byte, 0, total)
	for _, b := range buffers {
		out = append(out, b...)
	}
	return out
}

// sha256Hash returns SHA-256 of data.
func sha256Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// sha384Hash returns SHA-384 of data.
func sha384Hash(data []byte) []byte {
	h := sha512.Sum384(data)
	return h[:]
}

// encodeAVROLong encodes an int64 in AVRO zigzag varint format (used by the
// legacy deep hash path for serializing tags internally; kept for reference).
func encodeAVROLong(value int64) []byte {
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

// longTo32Bytes encodes a uint64 as a 32-byte little-endian buffer.
func longTo32BytesBE(value int) []byte {
	buf := make([]byte, 32)
	for i := len(buf) - 1; i >= 0; i-- {
		buf[i] = byte(value % 256)
		value /= 256
	}
	return buf
}

// bufferToInt converts a big-endian byte buffer to int.
func bufferToInt(buf []byte) int {
	value := 0
	for i := 0; i < len(buf); i++ {
		value = value*256 + int(buf[i])
	}
	return value
}

// intToBuffer converts int to 32-byte big-endian buffer (matches goar's intToBuffer).
func intToBuffer(note int) []byte {
	buffer := make([]byte, 32)
	for i := len(buffer) - 1; i >= 0; i-- {
		byt := note % 256
		buffer[i] = byte(byt)
		note = (note - byt) / 256
	}
	return buffer
}
