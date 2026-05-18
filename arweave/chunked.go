package arweave

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// =============================================================================
// Constants
// =============================================================================

const (
	// MaxChunkSize is the default Arweave data chunk size (256 KiB).
	MaxChunkSize = 256 * 1024
	// MinChunkSize is the minimum allowed chunk size.
	MinChunkSize = 32 * 1024
	// NoteSize is the size of offset notes in the Merkle tree (32 bytes).
	NoteSize = 32
	// HashSize is the SHA-256 output size.
	HashSize = 32
)

// =============================================================================
// Inline Merkle tree types (replaces goar/types)
// =============================================================================

type merkleChunks struct {
	DataRoot []byte
	Chunks   []merkleChunk
	Proofs   []*merkleProof
}

type merkleChunk struct {
	DataHash     []byte
	MinByteRange int
	MaxByteRange int
}

type merkleNode struct {
	ID           []byte
	Type         string // "branch" or "leaf"
	DataHash     []byte // leaf only
	MinByteRange int
	MaxByteRange int
	ByteRange    int       // branch only
	LeftChild    *merkleNode
	RightChild   *merkleNode
}

type merkleProof struct {
	Offset int
	Proof  []byte
}

// =============================================================================
// Chunk preparation (goar-compatible, no external deps)
// =============================================================================

// prepareChunks computes the Merkle tree, data_root, chunks, and proofs for
// the given data.  Mirrors goar's GenerateChunks.
func prepareChunks(data []byte) (*merkleChunks, error) {
	chunks := chunkData(data)
	leaves := generateLeaves(chunks)
	root := buildLayer(leaves)
	proofs := generateProofs(root)

	// Discard the last chunk & proof if it's zero-length.
	lastChunk := chunks[len(chunks)-1]
	if lastChunk.MaxByteRange-lastChunk.MinByteRange == 0 {
		chunks = chunks[:len(chunks)-1]
		proofs = proofs[:len(proofs)-1]
	}

	return &merkleChunks{
		DataRoot: root.ID,
		Chunks:   chunks,
		Proofs:   proofs,
	}, nil
}

// chunkData splits data into chunks of ~256 KiB, adjusting the split point
// so that the last chunk is not too small (< 32 KiB).
func chunkData(data []byte) []merkleChunk {
	var chunks []merkleChunk
	cursor := 0
	rest := data

	for len(rest) >= MaxChunkSize {
		chunkSize := MaxChunkSize
		// If the next remaining would be < MinChunkSize, split the rest evenly.
		nextChunkSize := len(rest) - MaxChunkSize
		if nextChunkSize > 0 && nextChunkSize < MinChunkSize {
			chunkSize = (len(rest) + 1) / 2 // ceil division
		}

		chunk := rest[:chunkSize]
		dataHash := sha256.Sum256(chunk)
		cursor += len(chunk)
		chunks = append(chunks, merkleChunk{
			DataHash:     dataHash[:],
			MinByteRange: cursor - len(chunk),
			MaxByteRange: cursor,
		})
		rest = rest[chunkSize:]
	}

	// Last chunk (may be empty).
	hash := sha256.Sum256(rest)
	chunks = append(chunks, merkleChunk{
		DataHash:     hash[:],
		MinByteRange: cursor,
		MaxByteRange: cursor + len(rest),
	})
	return chunks
}

// generateLeaves creates leaf nodes from data chunks.
func generateLeaves(chunks []merkleChunk) []*merkleNode {
	leaves := make([]*merkleNode, len(chunks))
	for i, ch := range chunks {
		leaves[i] = &merkleNode{
			ID: hashConcat([][]byte{
				hashConcat([][]byte{ch.DataHash}),
				hashConcat([][]byte{intToBuffer(ch.MaxByteRange)}),
			}),
			Type:         "leaf",
			DataHash:     ch.DataHash,
			MinByteRange: ch.MinByteRange,
			MaxByteRange: ch.MaxByteRange,
		}
	}
	return leaves
}

// buildLayer recursively builds the Merkle tree from leaf nodes upward.
func buildLayer(nodes []*merkleNode) *merkleNode {
	if len(nodes) == 1 {
		return nodes[0]
	}

	nextLayer := make([]*merkleNode, 0, (len(nodes)+1)/2)
	for i := 0; i < len(nodes); i += 2 {
		left := nodes[i]
		var right *merkleNode
		if i+1 < len(nodes) {
			right = nodes[i+1]
		}
		nextLayer = append(nextLayer, hashBranch(left, right))
	}
	return buildLayer(nextLayer)
}

// hashBranch creates a branch node from left and right children.
func hashBranch(left, right *merkleNode) *merkleNode {
	if right == nil {
		return left
	}

	hLeft := sha256Hash(left.ID)
	hRight := sha256Hash(right.ID)
	hMaxRange := sha256Hash(intToBuffer(left.MaxByteRange))

	id := hashConcat([][]byte{hLeft, hRight, hMaxRange})

	return &merkleNode{
		Type:         "branch",
		ID:           id,
		MaxByteRange: right.MaxByteRange,
		ByteRange:    left.MaxByteRange,
		LeftChild:    left,
		RightChild:   right,
	}
}

// generateProofs generates Merkle proofs for every leaf node.
func generateProofs(root *merkleNode) []*merkleProof {
	return resolveBranchProofs(root, []byte{})
}

// resolveBranchProofs recursively walks the tree to generate leaf proofs.
func resolveBranchProofs(node *merkleNode, proof []byte) []*merkleProof {
	if node.Type == "leaf" {
		return []*merkleProof{{
			Offset: node.MaxByteRange - 1,
			Proof: concatBuffer(
				proof,
				node.DataHash,
				intToBuffer(node.MaxByteRange),
			),
		}}
	}

	if node.Type == "branch" {
		partial := concatBuffer(
			proof,
			node.LeftChild.ID,
			node.RightChild.ID,
			intToBuffer(node.ByteRange),
		)
		left := resolveBranchProofs(node.LeftChild, partial)
		right := resolveBranchProofs(node.RightChild, partial)
		return append(left, right...)
	}

	return nil
}

// hashConcat concatenates byte slices and returns SHA-256 of the result.
func hashConcat(data [][]byte) []byte {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

// =============================================================================
// Chunk upload types (goar-compatible)
// =============================================================================

// chunkUpload is the JSON payload for POST /chunk.
type chunkUpload struct {
	DataRoot string `json:"data_root"`
	DataSize string `json:"data_size"`
	DataPath string `json:"data_path"`
	Offset   string `json:"offset"`
	Chunk    string `json:"chunk"`
}

// =============================================================================
// Chunked transaction types
// =============================================================================

// chunkedTx is a minimal transaction representation used during chunked
// uploads.  It mirrors goar's types.Transaction for the fields we need.
type chunkedTx struct {
	Format    int
	ID        string
	LastTx    string
	Owner     string
	Target    string
	Quantity  string
	Data      string
	DataSize  string
	DataRoot  string
	Reward    string
	Signature string
	Tags      []Tag
	Chunks    *merkleChunks
}

// =============================================================================
// Chunked upload methods on GatewayClient
// =============================================================================

// UploadDataChunked uploads data to Arweave using the chunked /chunk endpoint.
// It handles the full lifecycle:
//  1. Fetch anchor + reward
//  2. Prepare chunks (Merkle tree)
//  3. Sign with SHA-384 deep hash
//  4. Submit transaction (registers data_root)
//  5. Upload all chunks
//  6. Wait for confirmation
//
// For small data (<256KB), it also uses the chunked path (unified behavior).
// If confirmation times out, the transaction is returned with a nil status
// (not an error) because the tx has already been submitted.
func (gc *GatewayClient) UploadDataChunked(ctx context.Context, wallet *Wallet, data []byte, tags []Tag) (*Transaction, *TransactionStatus, error) {
	return gc.uploadDataChunked(ctx, wallet, data, int64(len(data)), tags)
}

// uploadDataChunked is the internal implementation.
func (gc *GatewayClient) uploadDataChunked(
	ctx context.Context,
	wallet *Wallet,
	data []byte,
	dataSize int64,
	tags []Tag,
) (*Transaction, *TransactionStatus, error) {
	// 1. Fetch anchor and reward.
	anchor, err := gc.GetAnchor(ctx)
	if err != nil {
		anchor = ""
	}

	reward, err := gc.GetReward(ctx, dataSize)
	if err != nil {
		reward = "0"
	}

	// 2. Build a chunkedTx with base64-encoded tags (goar convention).
	ct := &chunkedTx{
		Format:   2,
		Owner:    wallet.Owner,
		Target:   "",
		Quantity: "0",
		DataSize: strconv.FormatInt(dataSize, 10),
		Data:     "",
		Reward:   reward,
		LastTx:   anchor,
	}

	// Base64-encode tag names and values (goar convention for deep hash).
	ct.Tags = make([]Tag, len(tags))
	for i, t := range tags {
		ct.Tags[i] = Tag{
			Name:  base64.RawURLEncoding.EncodeToString([]byte(t.Name)),
			Value: base64.RawURLEncoding.EncodeToString([]byte(t.Value)),
		}
	}

	// 3. Prepare chunks (Merkle tree).
	if dataSize > 0 {
		mc, err := prepareChunks(data)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to prepare chunks: %w", err)
		}
		ct.Chunks = mc
		ct.DataRoot = base64.RawURLEncoding.EncodeToString(mc.DataRoot)
	}

	// 4. Sign with SHA-384 deep hash.
	if err := signChunkedTx(ct, wallet.PrivateKey); err != nil {
		return nil, nil, fmt.Errorf("failed to sign chunked tx: %w", err)
	}

	// 5. Submit the transaction (registers data_root on gateway).
	txID, err := gc.submitChunkedTx(ctx, ct)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to submit chunked tx: %w", err)
	}
	ct.ID = txID

	// 6. Upload all chunks.
	if dataSize > 0 && ct.Chunks != nil {
		if err := gc.uploadChunks(ctx, ct, data); err != nil {
			return nil, nil, fmt.Errorf("chunk upload failed: %w", err)
		}
	}

	// 7. Wait for confirmation.
	status, err := gc.WaitForConfirmation(ctx, txID, 120, 3*time.Second)
	if err != nil {
		// Tx submitted but unconfirmed — return tx without error.
		return chunkedTxToLegacy(ct), nil, nil
	}

	return chunkedTxToLegacy(ct), status, nil
}

// =============================================================================
// SHA-384 deep hash for chunked transactions
// =============================================================================

// signChunkedTx signs a chunkedTx using RSA-PSS SHA-256 over a SHA-384 deep hash.
// Mirrors goar's utils.SignTransaction.
func signChunkedTx(tx *chunkedTx, privKey *rsa.PrivateKey) error {
	sigData, err := chunkedTxSignatureData(tx)
	if err != nil {
		return err
	}
	sig, err := signPSS(privKey, sigData)
	if err != nil {
		return err
	}
	tx.Signature = base64.RawURLEncoding.EncodeToString(sig)

	idHash := sha256.Sum256(sig)
	tx.ID = base64.RawURLEncoding.EncodeToString(idHash[:])
	return nil
}

// chunkedTxSignatureData computes the deep hash for a chunkedTx using SHA-384.
func chunkedTxSignatureData(tx *chunkedTx) ([]byte, error) {
	// Convert tags to [][]string with base64-encoded values (already encoded).
	tags := make([][]string, len(tx.Tags))
	for i, t := range tx.Tags {
		tags[i] = []string{t.Name, t.Value}
	}

	dataList := []interface{}{
		base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(tx.Format))),
		tx.Owner,
		tx.Target,
		base64.RawURLEncoding.EncodeToString([]byte(tx.Quantity)),
		base64.RawURLEncoding.EncodeToString([]byte(tx.Reward)),
		tx.LastTx,
		tags,
		base64.RawURLEncoding.EncodeToString([]byte(tx.DataSize)),
		tx.DataRoot,
	}

	hash := deepHashList(dataList)
	return hash[:], nil
}

// =============================================================================
// HTTP helpers for chunked operations
// =============================================================================

// submitChunkedTx posts a chunked transaction (with empty data field) to /tx.
func (gc *GatewayClient) submitChunkedTx(ctx context.Context, tx *chunkedTx) (string, error) {
	m := map[string]interface{}{
		"format":    tx.Format,
		"id":        tx.ID,
		"last_tx":   tx.LastTx,
		"owner":     tx.Owner,
		"target":    tx.Target,
		"quantity":  tx.Quantity,
		"data":      "", // required — empty for chunked
		"data_size": tx.DataSize,
		"data_root": tx.DataRoot,
		"reward":    tx.Reward,
		"signature": tx.Signature,
		"tags":      tx.Tags,
	}

	body, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("failed to marshal chunked tx: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", gc.GatewayURL+"/tx", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := gc.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to submit chunked tx: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return "", fmt.Errorf("gateway returned %d: %s", resp.StatusCode, string(respBody))
	}

	return tx.ID, nil
}

// uploadChunks uploads all chunks for a transaction to /chunk.
func (gc *GatewayClient) uploadChunks(ctx context.Context, tx *chunkedTx, data []byte) error {
	for i := 0; i < len(tx.Chunks.Proofs); i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		proof := tx.Chunks.Proofs[i]
		ch := tx.Chunks.Chunks[i]

		cu := chunkUpload{
			DataRoot: tx.DataRoot,
			DataSize: tx.DataSize,
			DataPath: base64.RawURLEncoding.EncodeToString(proof.Proof),
			Offset:   strconv.Itoa(proof.Offset),
			Chunk:    base64.RawURLEncoding.EncodeToString(data[ch.MinByteRange:ch.MaxByteRange]),
		}

		body, err := json.Marshal(cu)
		if err != nil {
			return fmt.Errorf("failed to marshal chunk %d: %w", i, err)
		}

		req, err := http.NewRequestWithContext(ctx, "POST", gc.GatewayURL+"/chunk", bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("failed to create chunk request %d: %w", i, err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := gc.client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to upload chunk %d (offset %s): %w", i, cu.Offset, err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("gateway returned %d for chunk %d (offset %s)", resp.StatusCode, i, cu.Offset)
		}
	}
	return nil
}

// =============================================================================
// Conversion helpers
// =============================================================================

// chunkedTxToLegacy converts a chunkedTx to a legacy Transaction.
func chunkedTxToLegacy(ct *chunkedTx) *Transaction {
	// Decode base64-encoded tags back to plain text for the legacy struct.
	tags := make([]Tag, len(ct.Tags))
	for i, t := range ct.Tags {
		name, _ := base64.RawURLEncoding.DecodeString(t.Name)
		value, _ := base64.RawURLEncoding.DecodeString(t.Value)
		tags[i] = Tag{Name: string(name), Value: string(value)}
	}

	return &Transaction{
		Format:    ct.Format,
		ID:        ct.ID,
		LastTx:    ct.LastTx,
		Owner:     ct.Owner,
		Target:    ct.Target,
		Quantity:  ct.Quantity,
		Data:      ct.Data,
		DataSize:  ct.DataSize,
		DataRoot:  ct.DataRoot,
		Reward:    ct.Reward,
		Signature: ct.Signature,
		Tags:      tags,
	}
}

// =============================================================================
// Helpers
// =============================================================================

// signPSS signs data using RSA-PSS SHA-256.
func signPSS(privKey *rsa.PrivateKey, data []byte) ([]byte, error) {
	hashed := sha256.Sum256(data)
	return rsa.SignPSS(rand.Reader, privKey, crypto.SHA256, hashed[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	})
}

// time is used by WaitForConfirmation; imported via client.go.
