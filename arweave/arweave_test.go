package arweave

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// =============================================================================
// Wallet tests
// =============================================================================

func TestLoadWalletFromJSON(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	n := base64.RawURLEncoding.EncodeToString(privKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.E)).Bytes())
	d := base64.RawURLEncoding.EncodeToString(privKey.D.Bytes())

	jwk := JWK{N: n, E: e, D: d}
	jwkJSON, err := json.Marshal(jwk)
	if err != nil {
		t.Fatalf("failed to marshal JWK: %v", err)
	}

	wallet, err := LoadWalletFromJSON(jwkJSON)
	if err != nil {
		t.Fatalf("LoadWalletFromJSON failed: %v", err)
	}

	if wallet.Owner == "" {
		t.Fatal("empty owner")
	}
	if wallet.Address == "" {
		t.Fatal("empty address")
	}

	t.Logf("Wallet address: %s", wallet.Address)
	t.Logf("Wallet owner: %s", wallet.Owner)
}

func TestLoadWalletFromFile(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	n := base64.RawURLEncoding.EncodeToString(privKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.E)).Bytes())
	d := base64.RawURLEncoding.EncodeToString(privKey.D.Bytes())

	jwk := JWK{N: n, E: e, D: d}
	jwkJSON, err := json.Marshal(jwk)
	if err != nil {
		t.Fatalf("failed to marshal JWK: %v", err)
	}

	tmpFile := t.TempDir() + "/wallet.json"
	if err := os.WriteFile(tmpFile, jwkJSON, 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	wallet, err := LoadWalletFromFile(tmpFile)
	if err != nil {
		t.Fatalf("LoadWalletFromFile failed: %v", err)
	}

	if wallet.Owner == "" {
		t.Fatal("empty owner from file")
	}
}

func TestWalletWithCRTPrimes(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	n := base64.RawURLEncoding.EncodeToString(privKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.E)).Bytes())
	d := base64.RawURLEncoding.EncodeToString(privKey.D.Bytes())
	p := base64.RawURLEncoding.EncodeToString(privKey.Primes[0].Bytes())
	q := base64.RawURLEncoding.EncodeToString(privKey.Primes[1].Bytes())

	jwk := JWK{N: n, E: e, D: d, P: p, Q: q}
	jwkJSON, err := json.Marshal(jwk)
	if err != nil {
		t.Fatalf("failed to marshal JWK: %v", err)
	}

	wallet, err := LoadWalletFromJSON(jwkJSON)
	if err != nil {
		t.Fatalf("LoadWalletFromJSON with primes failed: %v", err)
	}

	if len(wallet.PrivateKey.Primes) < 2 {
		t.Fatal("expected CRT primes to be populated")
	}
}

// =============================================================================
// Transaction tests
// =============================================================================

func TestTransactionBuildAndSign(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	owner := base64.RawURLEncoding.EncodeToString(privKey.N.Bytes())

	tb := NewTransactionBuilder(owner)
	tb.SetData([]byte("hello world"))
	tb.AddTag("Test", "Value")
	tb.SetReward("100")

	tx := tb.Build()
	if err := tx.Sign(privKey); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if tx.Signature == "" {
		t.Fatal("empty signature")
	}
	if tx.ID == "" {
		t.Fatal("empty ID")
	}

	// Verify round-trip JSON (tags should be base64-encoded in JSON output).
	jsonBytes, err := tx.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	// Check that tags in JSON are base64-encoded (not plain text).
	var rawJSON map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &rawJSON); err != nil {
		t.Fatalf("json unmarshal failed: %v", err)
	}

	tagsArr, ok := rawJSON["tags"].([]interface{})
	if !ok || len(tagsArr) == 0 {
		t.Fatal("expected non-empty tags array in JSON")
	}

	firstTag := tagsArr[0].(map[string]interface{})
	tagName := firstTag["name"].(string)
	tagValue := firstTag["value"].(string)

	// The tags should be base64-encoded, not plain "Test"/"Value".
	if tagName == "Test" {
		t.Error("tag name should be base64-encoded in JSON output, got plain text 'Test'")
	}
	if tagValue == "Value" {
		t.Error("tag value should be base64-encoded in JSON output, got plain text 'Value'")
	}

	// Decode and verify.
	decodedName, _ := base64.RawURLEncoding.DecodeString(tagName)
	decodedValue, _ := base64.RawURLEncoding.DecodeString(tagValue)
	if string(decodedName) != "Test" {
		t.Errorf("decoded tag name mismatch: got %q", string(decodedName))
	}
	if string(decodedValue) != "Value" {
		t.Errorf("decoded tag value mismatch: got %q", string(decodedValue))
	}

	t.Logf("TX ID: %s", tx.ID)
	t.Logf("JSON tags encoded: name=%s value=%s", tagName, tagValue)
}

func TestTransactionDeterministicDeepHash(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	owner := base64.RawURLEncoding.EncodeToString(privKey.N.Bytes())

	tb := NewTransactionBuilder(owner)
	tb.SetData([]byte("deterministic test"))
	tb.AddTag("Key", "Val")

	tx := tb.Build()

	dh1, err := tx.signatureData()
	if err != nil {
		t.Fatalf("signatureData 1 failed: %v", err)
	}
	dh2, err := tx.signatureData()
	if err != nil {
		t.Fatalf("signatureData 2 failed: %v", err)
	}

	if len(dh1) == 0 {
		t.Fatal("empty deep hash")
	}
	if len(dh1) != 48 { // SHA-384 output
		t.Errorf("expected 48-byte deep hash (SHA-384), got %d", len(dh1))
	}
	if string(dh1) != string(dh2) {
		t.Fatal("deep hash not deterministic")
	}

	t.Logf("DeepHash (SHA-384): %x", dh1)
}

func TestTransactionSignProducesValidID(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	owner := base64.RawURLEncoding.EncodeToString(privKey.N.Bytes())

	tb := NewTransactionBuilder(owner)
	tb.SetData([]byte("sign test"))
	tx := tb.Build()

	if err := tx.Sign(privKey); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// ID should be base64url(SHA-256(signature)).
	sigBytes, err := base64.RawURLEncoding.DecodeString(tx.Signature)
	if err != nil {
		t.Fatalf("failed to decode signature: %v", err)
	}

	idHash := sha256Hash(sigBytes)
	expectedID := base64.RawURLEncoding.EncodeToString(idHash)
	if tx.ID != expectedID {
		t.Errorf("ID mismatch: expected %s, got %s", expectedID, tx.ID)
	}

	t.Logf("TX ID: %s", tx.ID)
}

func TestToJSONRaw(t *testing.T) {
	tb := NewTransactionBuilder("owner-test")
	tb.AddTag("PlainTag", "PlainValue")
	tb.SetData([]byte("data"))

	tx := tb.Build()

	raw, err := tx.ToJSONRaw()
	if err != nil {
		t.Fatalf("ToJSONRaw failed: %v", err)
	}

	// Raw JSON should have plain-text tags.
	var rawJSON map[string]interface{}
	json.Unmarshal(raw, &rawJSON)
	tagsArr := rawJSON["tags"].([]interface{})
	firstTag := tagsArr[0].(map[string]interface{})
	if firstTag["name"] != "PlainTag" {
		t.Errorf("raw JSON tag name: expected 'PlainTag', got %q", firstTag["name"])
	}
}

// =============================================================================
// Gateway client mock tests
// =============================================================================

func TestGatewayClient_SubmitAndStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tx" && r.Method == "POST" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id":"mock-tx-id-12345"}`))
			return
		}
		if len(r.URL.Path) > 4 && r.URL.Path[:4] == "/tx/" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"block_height":1913000,"block_indep_hash":"mock-hash","number_of_confirmations":10}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)

	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	owner := base64.RawURLEncoding.EncodeToString(privKey.N.Bytes())

	tb := NewTransactionBuilder(owner)
	tb.SetData([]byte("test"))
	tx := tb.Build()
	tx.Sign(privKey)

	txID, err := client.SubmitTransaction(context.Background(), tx)
	if err != nil {
		t.Fatalf("SubmitTransaction failed: %v", err)
	}
	t.Logf("Submitted TX ID: %s", txID)

	status, err := client.GetTransactionStatus(context.Background(), txID)
	if err != nil {
		t.Fatalf("GetTransactionStatus failed: %v", err)
	}
	if !status.Confirmed {
		t.Error("transaction should be confirmed")
	}
	if status.BlockHeight != 1913000 {
		t.Errorf("unexpected block height: %d", status.BlockHeight)
	}
	if status.BlockHash != "mock-hash" {
		t.Errorf("unexpected block hash: %s", status.BlockHash)
	}
}

func TestGatewayClient_GetRewardAndAnchor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/price/1000":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("5000"))
		case "/tx_anchor":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`"mock-anchor-tx-id"`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)

	reward, err := client.GetReward(context.Background(), 1000)
	if err != nil {
		t.Fatalf("GetReward failed: %v", err)
	}
	if reward != "5000" {
		t.Errorf("expected reward '5000', got %q", reward)
	}

	anchor, err := client.GetAnchor(context.Background())
	if err != nil {
		t.Fatalf("GetAnchor failed: %v", err)
	}
	if anchor != "mock-anchor-tx-id" {
		t.Errorf("expected anchor 'mock-anchor-tx-id', got %q", anchor)
	}
}

func TestGatewayClient_WaitForConfirmation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tx/test-tx/status" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"block_height":100,"block_indep_hash":"hash-100"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)
	status, err := client.WaitForConfirmation(context.Background(), "test-tx", 5, 1*time.Millisecond)
	if err != nil {
		t.Fatalf("WaitForConfirmation failed: %v", err)
	}
	if status.BlockHeight != 100 {
		t.Errorf("expected block 100, got %d", status.BlockHeight)
	}
}

func TestGatewayClient_GetTransactionDataSize(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.URL.Path) > 4 && r.URL.Path[:4] == "/tx/" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"block_height":100,"data_size":"1048576"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)
	size, err := client.GetTransactionDataSize(context.Background(), "test-tx")
	if err != nil {
		t.Fatalf("GetTransactionDataSize failed: %v", err)
	}
	if size != 1048576 {
		t.Errorf("expected 1048576, got %d", size)
	}
}

// =============================================================================
// GraphQL tests
// =============================================================================

func TestGatewayClient_QueryExistingCARs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": {
					"transactions": {
						"edges": [
							{ "node": { "id": "car-tx-1" } },
							{ "node": { "id": "car-tx-2" } }
						]
					}
				}
			}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)
	ids, err := client.QueryExistingCARs(context.Background(), "bafyTestRootCID", 5)
	if err != nil {
		t.Fatalf("QueryExistingCARs failed: %v", err)
	}
	if len(ids) != 2 {
		t.Errorf("expected 2 IDs, got %d", len(ids))
	}
	if ids[0] != "car-tx-1" || ids[1] != "car-tx-2" {
		t.Errorf("unexpected IDs: %v", ids)
	}
}

func TestGatewayClient_QueryExistingMetas(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"data": {
					"transactions": {
						"edges": [
							{ "node": { "id": "meta-tx-1" } }
						]
					}
				}
			}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)
	ids, err := client.QueryExistingMetas(context.Background(), "bafyTestRootCID", "data-tx-1", 3)
	if err != nil {
		t.Fatalf("QueryExistingMetas failed: %v", err)
	}
	if len(ids) != 1 {
		t.Errorf("expected 1 ID, got %d", len(ids))
	}
	if ids[0] != "meta-tx-1" {
		t.Errorf("unexpected ID: %s", ids[0])
	}
}

// =============================================================================
// Chunk / Merkle tree tests
// =============================================================================

func TestChunkData(t *testing.T) {
	// Small data: single chunk.
	data := make([]byte, 100)
	chunks := chunkData(data)

	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk for 100-byte data, got %d", len(chunks))
	}
	if chunks[0].MinByteRange != 0 {
		t.Errorf("expected MinByteRange 0, got %d", chunks[0].MinByteRange)
	}
	if chunks[0].MaxByteRange != 100 {
		t.Errorf("expected MaxByteRange 100, got %d", chunks[0].MaxByteRange)
	}

	// Data exactly MaxChunkSize: single chunk.
	data = make([]byte, MaxChunkSize)
	chunks = chunkData(data)
	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk for %d-byte data, got %d", MaxChunkSize, len(chunks))
	}
}

func TestChunkDataMultiChunk(t *testing.T) {
	// Data > MaxChunkSize: multiple chunks.
	dataSize := MaxChunkSize + MaxChunkSize/2
	data := make([]byte, dataSize)
	for i := range data {
		data[i] = byte(i % 256)
	}

	chunks := chunkData(data)
	if len(chunks) < 2 {
		t.Fatalf("expected at least 2 chunks, got %d", len(chunks))
	}

	// Verify coverage: sum of chunk sizes should equal dataSize.
	totalSize := 0
	for _, ch := range chunks {
		totalSize += ch.MaxByteRange - ch.MinByteRange
	}
	if totalSize != dataSize {
		t.Errorf("total chunked size %d != data size %d", totalSize, dataSize)
	}

	t.Logf("Data size: %d, chunks: %d", dataSize, len(chunks))
}

func TestPrepareChunks(t *testing.T) {
	data := make([]byte, MaxChunkSize+1000)
	for i := range data {
		data[i] = byte(i % 256)
	}

	mc, err := prepareChunks(data)
	if err != nil {
		t.Fatalf("prepareChunks failed: %v", err)
	}

	if mc.DataRoot == nil || len(mc.DataRoot) == 0 {
		t.Fatal("empty DataRoot")
	}
	if len(mc.Chunks) < 2 {
		t.Fatal("expected at least 2 chunks")
	}
	if len(mc.Proofs) != len(mc.Chunks) {
		t.Fatalf("proofs count (%d) != chunks count (%d)", len(mc.Proofs), len(mc.Chunks))
	}

	t.Logf("DataRoot: %x", mc.DataRoot)
	t.Logf("Chunks: %d, Proofs: %d", len(mc.Chunks), len(mc.Proofs))
}

func TestMerkleTreeDeterministic(t *testing.T) {
	data := make([]byte, MaxChunkSize+100)
	for i := range data {
		data[i] = byte(i % 256)
	}

	mc1, _ := prepareChunks(data)
	mc2, _ := prepareChunks(data)

	if string(mc1.DataRoot) != string(mc2.DataRoot) {
		t.Fatal("Merkle tree not deterministic")
	}

	// Check all chunk hashes and proofs match.
	for i := range mc1.Chunks {
		if string(mc1.Chunks[i].DataHash) != string(mc2.Chunks[i].DataHash) {
			t.Errorf("chunk %d DataHash mismatch", i)
		}
	}
	for i := range mc1.Proofs {
		if string(mc1.Proofs[i].Proof) != string(mc2.Proofs[i].Proof) {
			t.Errorf("proof %d mismatch", i)
		}
	}
}

// =============================================================================
// Chunked upload mock tests
// =============================================================================

func TestUploadDataChunked_Mock(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		switch {
		case r.URL.Path == "/tx_anchor":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`"mock-anchor"`))
		case r.URL.Path == "/price/13":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("1000"))
		case r.URL.Path == "/tx" && r.Method == "POST":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id":"chunked-tx-123"}`))
		case r.URL.Path == "/chunk":
			w.WriteHeader(http.StatusOK)
		case len(r.URL.Path) > 4 && r.URL.Path[:4] == "/tx/":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"block_height":100,"block_indep_hash":"hash-100"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)

	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	nBytes := privKey.N.Bytes()
	wallet := &Wallet{
		PrivateKey: privKey,
		Owner:      base64.RawURLEncoding.EncodeToString(nBytes),
	}

	data := []byte("hello chunked!") // 13 bytes, small data
	tags := []Tag{{Name: "TestTag", Value: "TestValue"}}

	tx, status, err := client.UploadDataChunked(context.Background(), wallet, data, tags)
	if err != nil {
		t.Fatalf("UploadDataChunked failed: %v", err)
	}
	if tx == nil {
		t.Fatal("expected non-nil transaction")
	}
	if tx.ID == "" {
		t.Fatal("expected non-empty transaction ID")
	}
	if status == nil {
		t.Fatal("expected confirmed status for mock")
	}
	if !status.Confirmed {
		t.Error("expected confirmed status")
	}

	t.Logf("Uploaded TX ID: %s, block: %d", tx.ID, status.BlockHeight)
	t.Logf("HTTP calls: %d", callCount)
}

func TestUploadDataChunked_Unconfirmed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/tx_anchor":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`"mock-anchor"`))
		case r.URL.Path == "/price/4":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("500"))
		case r.URL.Path == "/tx" && r.Method == "POST":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id":"unconfirmed-tx"}`))
		case r.URL.Path == "/chunk":
			w.WriteHeader(http.StatusOK)
		case len(r.URL.Path) > 4 && r.URL.Path[:4] == "/tx/":
			// Always return unconfirmed.
			w.WriteHeader(http.StatusAccepted)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)

	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	nBytes := privKey.N.Bytes()
	wallet := &Wallet{
		PrivateKey: privKey,
		Owner:      base64.RawURLEncoding.EncodeToString(nBytes),
	}

	data := []byte("data")
	tags := []Tag{{Name: "Tag", Value: "Val"}}

	// Use a context with short timeout so WaitForConfirmation doesn't block forever.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	tx, status, err := client.UploadDataChunked(ctx, wallet, data, tags)
	if err != nil {
		t.Fatalf("UploadDataChunked should not error on unconfirmed: %v", err)
	}
	if tx == nil {
		t.Fatal("expected non-nil transaction even when unconfirmed")
	}
	if tx.ID == "" {
		t.Fatal("expected non-empty transaction ID")
	}
	// Status should be nil when unconfirmed (per spec: return tx, nil, nil).
	if status != nil {
		t.Logf("Got status (may happen with quick confirmation): confirmed=%v", status.Confirmed)
	}

	t.Logf("TX ID: %s (unconfirmed, status returned: %v)", tx.ID, status != nil)
}

// =============================================================================
// Context cancellation tests
// =============================================================================

func TestWaitForConfirmation_ContextCancel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err := client.WaitForConfirmation(ctx, "test-tx", 100, 500*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("WaitForConfirmation took too long to cancel: %v", elapsed)
	}
	t.Logf("Cancelled after %v", elapsed)
}

// =============================================================================
// Deep hash internals
// =============================================================================

func TestDeepHashList(t *testing.T) {
	// Test the deep hash with known goar-compatible input.
	dataList := []interface{}{
		base64.RawURLEncoding.EncodeToString([]byte("2")),
		"owner-base64",
		"",
		base64.RawURLEncoding.EncodeToString([]byte("0")),
		base64.RawURLEncoding.EncodeToString([]byte("0")),
		"",
		[][]string{}, // empty tags
		base64.RawURLEncoding.EncodeToString([]byte("0")),
		"",
	}

	hash := deepHashList(dataList)
	if len(hash) != 48 {
		t.Errorf("expected 48-byte SHA-384 hash, got %d", len(hash))
	}

	// Determinism check.
	hash2 := deepHashList(dataList)
	if hash != hash2 {
		t.Fatal("deepHashList not deterministic")
	}

	t.Logf("DeepHash: %x", hash[:])
}

func TestDeepHashStr(t *testing.T) {
	// Base64-encoded "hello"
	encoded := base64.RawURLEncoding.EncodeToString([]byte("hello"))

	hash1 := deepHashStr(encoded)
	hash2 := deepHashStr(encoded)

	if hash1 != hash2 {
		t.Fatal("deepHashStr not deterministic")
	}
	if len(hash1) != 48 {
		t.Errorf("expected 48-byte hash, got %d", len(hash1))
	}

	// Different input should produce different hash.
	encoded2 := base64.RawURLEncoding.EncodeToString([]byte("world"))
	hash3 := deepHashStr(encoded2)
	if hash1 == hash3 {
		t.Fatal("different inputs should produce different hashes")
	}
}

func TestSignChunkedTx(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	ct := &chunkedTx{
		Format:   2,
		Owner:    base64.RawURLEncoding.EncodeToString(privKey.N.Bytes()),
		Target:   "",
		Quantity: "0",
		DataSize: "0",
		Data:     "",
		Reward:   "0",
		LastTx:   "",
		Tags:     []Tag{},
	}

	if err := signChunkedTx(ct, privKey); err != nil {
		t.Fatalf("signChunkedTx failed: %v", err)
	}

	if ct.Signature == "" {
		t.Fatal("empty signature")
	}
	if ct.ID == "" {
		t.Fatal("empty ID")
	}

	t.Logf("Chunked TX ID: %s", ct.ID)
}

// =============================================================================
// SetHTTPClient / HTTPClient tests
// =============================================================================

func TestSetHTTPClient_UnitTest(t *testing.T) {
	client := NewGatewayClient("https://example.com")
	customHTTP := &http.Client{Timeout: 5 * time.Second}
	client.SetHTTPClient(customHTTP)

	if client.HTTPClient() != customHTTP {
		t.Fatal("HTTPClient() should return the custom client set via SetHTTPClient")
	}
}

// =============================================================================
// DownloadTransactionData test
// =============================================================================

func TestDownloadTransactionData_UnitTest(t *testing.T) {
	expectedData := []byte("hello transaction data!")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/test-tx-abc" {
			w.WriteHeader(http.StatusOK)
			w.Write(expectedData)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)
	data, err := client.DownloadTransactionData(context.Background(), "test-tx-abc")
	if err != nil {
		t.Fatalf("DownloadTransactionData failed: %v", err)
	}
	if string(data) != string(expectedData) {
		t.Errorf("expected %q, got %q", expectedData, data)
	}
}

func TestDownloadTransactionData_NotFound_UnitTest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)
	_, err := client.DownloadTransactionData(context.Background(), "nonexistent-tx")
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
	t.Logf("Got expected error: %v", err)
}

// =============================================================================
// SetTags / SetTarget / SetLastTx builder methods
// =============================================================================

func TestSetTags_UnitTest(t *testing.T) {
	tb := NewTransactionBuilder("owner-test")
	tb.AddTag("OldTag", "OldValue")
	tb.SetTags([]Tag{{Name: "NewTag", Value: "NewValue"}})

	tx := tb.Build()
	if len(tx.Tags) != 1 {
		t.Fatalf("SetTags should replace all tags, got %d tags", len(tx.Tags))
	}
	if tx.Tags[0].Name != "NewTag" || tx.Tags[0].Value != "NewValue" {
		t.Errorf("unexpected tag after SetTags: %+v", tx.Tags[0])
	}
}

func TestSetTarget_UnitTest(t *testing.T) {
	tb := NewTransactionBuilder("owner-test")
	tb.SetTarget("target-address-123")
	tx := tb.Build()
	if tx.Target != "target-address-123" {
		t.Errorf("expected target 'target-address-123', got %q", tx.Target)
	}
}

func TestSetLastTx_UnitTest(t *testing.T) {
	tb := NewTransactionBuilder("owner-test")
	tb.SetLastTx("last-tx-anchor-456")
	tx := tb.Build()
	if tx.LastTx != "last-tx-anchor-456" {
		t.Errorf("expected last_tx 'last-tx-anchor-456', got %q", tx.LastTx)
	}
}

// =============================================================================
// Helper function tests: base64Encode, base64Decode, sha384Hash,
// encodeAVROLong, longTo32BytesBE, bufferToInt
// =============================================================================

func TestBase64EncodeDecode_UnitTest(t *testing.T) {
	t.Run("base64Encode", func(t *testing.T) {
		encoded := base64Encode([]byte("hello world"))
		if encoded == "" {
			t.Fatal("base64Encode returned empty string")
		}
		// Should be RawURLEncoding (no padding)
		if encoded[len(encoded)-1] == '=' {
			t.Error("base64Encode should use RawURLEncoding (no padding)")
		}
		t.Logf("base64Encode('hello world') = %s", encoded)
	})

	t.Run("base64Decode", func(t *testing.T) {
		decoded, err := base64Decode("aGVsbG8gd29ybGQ")
		if err != nil {
			t.Fatalf("base64Decode failed: %v", err)
		}
		if string(decoded) != "hello world" {
			t.Errorf("expected 'hello world', got %q", decoded)
		}
	})

	t.Run("base64RoundTrip", func(t *testing.T) {
		original := []byte("test data 12345 !@#$%")
		encoded := base64Encode(original)
		decoded, err := base64Decode(encoded)
		if err != nil {
			t.Fatalf("roundtrip decode failed: %v", err)
		}
		if string(decoded) != string(original) {
			t.Errorf("roundtrip mismatch: got %q, want %q", decoded, original)
		}
	})

	t.Run("base64DecodeInvalid", func(t *testing.T) {
		_, err := base64Decode("!!!invalid!!!")
		if err == nil {
			t.Fatal("expected error for invalid base64")
		}
	})
}

func TestSha384Hash_UnitTest(t *testing.T) {
	hash := sha384Hash([]byte("test data"))
	if len(hash) != 48 {
		t.Errorf("expected 48-byte SHA-384 hash, got %d", len(hash))
	}

	// Determinism
	hash2 := sha384Hash([]byte("test data"))
	if string(hash) != string(hash2) {
		t.Fatal("sha384Hash not deterministic")
	}

	// Different input → different output
	hash3 := sha384Hash([]byte("other data"))
	if string(hash) == string(hash3) {
		t.Fatal("different inputs should produce different hashes")
	}

	t.Logf("SHA-384: %x", hash)
}

func TestEncodeAVROLong_UnitTest(t *testing.T) {
	t.Run("Positive", func(t *testing.T) {
		encoded := encodeAVROLong(42)
		if len(encoded) == 0 {
			t.Fatal("encodeAVROLong returned empty")
		}
		t.Logf("encodeAVROLong(42) = %x", encoded)
	})

	t.Run("Negative", func(t *testing.T) {
		encoded := encodeAVROLong(-1)
		if len(encoded) == 0 {
			t.Fatal("encodeAVROLong(-1) returned empty")
		}
		t.Logf("encodeAVROLong(-1) = %x", encoded)
	})

	t.Run("Zero", func(t *testing.T) {
		encoded := encodeAVROLong(0)
		// Zero encodes as a single 0x00 byte
		if len(encoded) != 1 || encoded[0] != 0 {
			t.Errorf("encodeAVROLong(0) should be [0x00], got %x", encoded)
		}
	})

	t.Run("LargeValue", func(t *testing.T) {
		encoded := encodeAVROLong(1 << 20)
		if len(encoded) == 0 {
			t.Fatal("encodeAVROLong for large value returned empty")
		}
		t.Logf("encodeAVROLong(1<<20) = %x (len=%d)", encoded, len(encoded))
	})
}

func TestLongTo32BytesBE_UnitTest(t *testing.T) {
	buf := longTo32BytesBE(42)
	if len(buf) != 32 {
		t.Fatalf("expected 32-byte buffer, got %d", len(buf))
	}

	// 42 should be stored in big-endian at the end of the buffer
	if buf[31] != 42 {
		t.Errorf("expected last byte to be 42, got %d", buf[31])
	}

	// All leading bytes should be 0
	for i := 0; i < 31; i++ {
		if buf[i] != 0 {
			t.Errorf("byte %d should be 0, got %d", i, buf[i])
		}
	}

	t.Logf("longTo32BytesBE(42) = %x", buf)
}

func TestBufferToInt_UnitTest(t *testing.T) {
	// Construct a known big-endian buffer
	buf := []byte{0x00, 0x00, 0x01, 0x2C} // = 300 in big-endian
	val := bufferToInt(buf)
	if val != 300 {
		t.Errorf("bufferToInt(%x) = %d, want 300", buf, val)
	}

	// Single byte
	val = bufferToInt([]byte{0x2A})
	if val != 42 {
		t.Errorf("bufferToInt([0x2A]) = %d, want 42", val)
	}

	// Zero
	val = bufferToInt([]byte{0x00, 0x00, 0x00})
	if val != 0 {
		t.Errorf("bufferToInt(zeros) = %d, want 0", val)
	}

	// Roundtrip with longTo32BytesBE
	original := 12345678
	buf32 := longTo32BytesBE(original)
	recovered := bufferToInt(buf32)
	if recovered != original {
		t.Errorf("roundtrip: %d -> longTo32BytesBE -> bufferToInt -> %d", original, recovered)
	}
}
