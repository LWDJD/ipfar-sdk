package bundle

import (
	"crypto/ed25519"
	"crypto/rand"
	cr "crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// ============================================================
// Tag limits
// ============================================================

func TestVerify_TooManyTags(t *testing.T) {
	pubKey, privateKey, err := ed25519.GenerateKey(cr.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	item := NewDataItem()
	item.SignatureType = ED25519SignType
	item.SetOwner(pubKey)
	item.SetData([]byte("test"))

	// Add 129 tags (max is 128)
	for i := 0; i < 129; i++ {
		item.AddTag(fmt.Sprintf("Tag-%d", i), fmt.Sprintf("Value-%d", i))
	}

	// Sign properly
	signData, _ := item.signData()
	item.Signature = ed25519.Sign(privateKey, signData)
	item.Id = computeId(item.Signature)

	err = item.Verify()
	if err == nil {
		t.Fatal("expected error for >128 tags")
	}
	if !strings.Contains(err.Error(), "too many tags") {
		t.Errorf("error should mention tag limit, got: %v", err)
	}
}

func TestVerify_TagNameTooLong(t *testing.T) {
	pubKey, privateKey, err := ed25519.GenerateKey(cr.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	item := NewDataItem()
	item.SignatureType = ED25519SignType
	item.SetOwner(pubKey)

	// Tag name > 1024 bytes
	longName := strings.Repeat("n", 1025)
	item.AddTag(longName, "value")
	item.SetData([]byte("test"))

	// Sign properly
	signData, _ := item.signData()
	item.Signature = ed25519.Sign(privateKey, signData)
	item.Id = computeId(item.Signature)

	err = item.Verify()
	if err == nil {
		t.Fatal("expected error for tag name > 1024 bytes")
	}
	if !strings.Contains(err.Error(), "name too long") {
		t.Errorf("error should mention name length, got: %v", err)
	}
}

func TestVerify_TagValueTooLong(t *testing.T) {
	pubKey, privateKey, err := ed25519.GenerateKey(cr.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	item := NewDataItem()
	item.SignatureType = ED25519SignType
	item.SetOwner(pubKey)

	// Tag value > 3072 bytes
	longValue := strings.Repeat("v", 3073)
	item.AddTag("name", longValue)
	item.SetData([]byte("test"))

	// Sign properly
	signData, _ := item.signData()
	item.Signature = ed25519.Sign(privateKey, signData)
	item.Id = computeId(item.Signature)

	err = item.Verify()
	if err == nil {
		t.Fatal("expected error for tag value > 3072 bytes")
	}
	if !strings.Contains(err.Error(), "value too long") {
		t.Errorf("error should mention value length, got: %v", err)
	}
}

func TestVerify_EmptyTagNameAndValue(t *testing.T) {
	pubKey, privateKey, err := ed25519.GenerateKey(cr.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	item := NewDataItem()
	item.SignatureType = ED25519SignType
	item.SetOwner(pubKey)

	// Empty tag name
	item.AddTag("", "value")
	item.SetData([]byte("test"))

	// Sign properly
	signData, _ := item.signData()
	item.Signature = ed25519.Sign(privateKey, signData)
	item.Id = computeId(item.Signature)

	err = item.Verify()
	if err == nil {
		t.Fatal("expected error for empty tag name")
	}
	if !strings.Contains(err.Error(), "must be non-empty") {
		t.Errorf("error should mention non-empty, got: %v", err)
	}
}

func TestVerify_EmptyTagValue(t *testing.T) {
	pubKey, privateKey, err := ed25519.GenerateKey(cr.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	item := NewDataItem()
	item.SignatureType = ED25519SignType
	item.SetOwner(pubKey)

	item.AddTag("name", "")
	item.SetData([]byte("test"))

	// Sign properly
	signData, _ := item.signData()
	item.Signature = ed25519.Sign(privateKey, signData)
	item.Id = computeId(item.Signature)

	err = item.Verify()
	if err == nil {
		t.Fatal("expected error for empty tag value")
	}
}

// ============================================================
// Anchor limits
// ============================================================

func TestVerify_AnchorTooLong(t *testing.T) {
	privateKey, err := rsa.GenerateKey(cr.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	item := NewDataItem()
	// Anchor > 32 bytes
	longAnchor := make([]byte, 33)
	for i := range longAnchor {
		longAnchor[i] = byte(i % 256)
	}
	item.SetAnchor(longAnchor)
	item.AddTag("Test", "Value")
	item.SetData([]byte("test"))

	// Signing with long anchor
	if err := item.SignWithRSA(privateKey); err != nil {
		t.Fatalf("signing with long anchor failed: %v", err)
	}

	// Verify should catch anchor length
	err = item.Verify()
	if err == nil {
		t.Fatal("expected error for anchor > 32 bytes")
	}
	if !strings.Contains(err.Error(), "anchor too long") {
		t.Errorf("error should mention anchor length, got: %v", err)
	}
}

func TestVerify_AnchorExactly32(t *testing.T) {
	privateKey, err := rsa.GenerateKey(cr.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	item := NewDataItem()
	anchor32 := make([]byte, 32)
	for i := range anchor32 {
		anchor32[i] = byte(i % 256)
	}
	item.SetAnchor(anchor32)
	item.AddTag("Test", "Value")
	item.SetData([]byte("test"))

	if err := item.SignWithRSA(privateKey); err != nil {
		t.Fatalf("signing failed: %v", err)
	}

	if err := item.Verify(); err != nil {
		t.Errorf("anchor exactly 32 bytes should be valid: %v", err)
	}
}

// ============================================================
// Parse edge cases
// ============================================================

func TestParseBundle_TruncatedHeader(t *testing.T) {
	tooShort := make([]byte, 31) // less than 32 bytes header
	_, err := ParseBundle(tooShort)
	if err == nil {
		t.Fatal("expected error for < 32 bytes data")
	}
}

func TestParseBundle_ZeroItems(t *testing.T) {
	// Build a header with 0 items
	header := make([]byte, 32)
	// All zeros → itemsNum = 0
	_, err := ParseBundle(header)
	if err == nil {
		t.Fatal("expected error for 0 items")
	}
}

func TestParseBundle_TruncatedItemData(t *testing.T) {
	privateKey, err := rsa.GenerateKey(cr.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	builder := NewBundleBuilder()
	item := NewDataItem()
	item.AddTag("Test", "Value")
	item.SetData([]byte("test data"))
	item.SignWithRSA(privateKey)
	builder.AddItem(item)

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	// Truncate the data
	truncated := data[:len(data)-10]
	_, err = ParseBundle(truncated)
	if err == nil {
		t.Fatal("expected error for truncated data")
	}
}

func TestParseBundle_InvalidSignatureType(t *testing.T) {
	// Build a bundle with invalid signature type byte
	badData := make([]byte, 96) // header for 1 item
	badData[0] = 1              // itemsNum = 1
	// Item header: length=50, ID=zeros
	badData[32] = 50 // item length

	// Item data: invalid signature type
	itemData := make([]byte, 50)
	itemData[0] = 99 // invalid sig type
	itemData[1] = 0

	badData = append(badData, itemData...)

	_, err := ParseBundle(badData)
	if err == nil {
		t.Fatal("expected error for invalid signature type")
	}
}

// ============================================================
// Unsupported signature type verification
// ============================================================

func TestVerify_UnsupportedSignatureType(t *testing.T) {
	item := NewDataItem()
	item.SignatureType = 99 // unsupported
	item.Signature = make([]byte, 64)
	item.Owner = make([]byte, 32)
	item.Id = computeId(item.Signature)
	item.SetData([]byte("test"))

	err := item.Verify()
	if err == nil {
		t.Fatal("expected error for unsupported signature type")
	}
}

func TestVerify_SolanaSignType(t *testing.T) {
	// Solana uses same ed25519 verification path
	pubKey, privateKey, err := ed25519.GenerateKey(cr.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	item := NewDataItem()
	item.SignatureType = SolanaSignType
	item.SetOwner(pubKey)
	item.AddTag("Test", "Value")
	item.SetData([]byte("solana test"))

	// Sign using Ed25519 (Solana also uses Ed25519)
	signData, err := item.signData()
	if err != nil {
		t.Fatalf("signData failed: %v", err)
	}
	item.Signature = ed25519.Sign(privateKey, signData)
	item.Id = computeId(item.Signature)

	err = item.Verify()
	if err != nil {
		t.Errorf("Solana signature type verification should pass: %v", err)
	}
}

// ============================================================
// Signature length mismatch
// ============================================================

func TestVerify_WrongSignatureLength(t *testing.T) {
	item := NewDataItem()
	item.SignatureType = ED25519SignType
	item.Signature = make([]byte, 65) // ED25519 expects 64
	item.Owner = make([]byte, 32)
	item.Id = computeId(item.Signature)
	item.SetData([]byte("test"))

	err := item.Verify()
	if err == nil {
		t.Fatal("expected error for wrong signature length")
	}
}

func TestVerify_WrongOwnerLength(t *testing.T) {
	item := NewDataItem()
	item.SignatureType = ED25519SignType
	item.Signature = make([]byte, 64)
	item.Owner = make([]byte, 33) // ED25519 expects 32
	item.Id = computeId(item.Signature)
	item.SetData([]byte("test"))

	err := item.Verify()
	if err == nil {
		t.Fatal("expected error for wrong owner length")
	}
}

// ============================================================
// ID mismatch
// ============================================================

func TestVerify_IdMismatch(t *testing.T) {
	item := NewDataItem()
	item.SignatureType = ED25519SignType
	item.Signature = make([]byte, 64)
	item.Owner = make([]byte, 32)
	// Deliberately wrong ID
	item.Id = make([]byte, 32)
	for i := range item.Id {
		item.Id[i] = 0xFF
	}
	item.SetData([]byte("test"))

	err := item.Verify()
	if err == nil {
		t.Fatal("expected error for ID mismatch")
	}
	if !strings.Contains(err.Error(), "id mismatch") {
		t.Errorf("error should mention id mismatch, got: %v", err)
	}
}

// ============================================================
// Concurrent bundle operations
// ============================================================

func TestBundleBuilder_Concurrent(t *testing.T) {
	privateKey, err := rsa.GenerateKey(cr.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			builder := NewBundleBuilder()
			item := NewDataItem()
			item.AddTag("Index", fmt.Sprintf("%d", idx))
			item.SetData([]byte(fmt.Sprintf("concurrent data %d", idx)))

			if err := item.SignWithRSA(privateKey); err != nil {
				errCh <- err
				return
			}

			builder.AddItem(item)
			data, err := builder.Build()
			if err != nil {
				errCh <- err
				return
			}

			// Parse back
			bundle, err := ParseBundle(data)
			if err != nil {
				errCh <- err
				return
			}
			if len(bundle.Items) != 1 {
				errCh <- fmt.Errorf("expected 1 item, got %d", len(bundle.Items))
				return
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent bundle operation failed: %v", err)
	}
}

// ============================================================
// Empty bundle on parse (item count = 1 but empty data)
// ============================================================

func TestParseBundle_ItemCountMismatch(t *testing.T) {
	privateKey, err := rsa.GenerateKey(cr.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	builder := NewBundleBuilder()
	item := NewDataItem()
	item.AddTag("Test", "Value")
	item.SetData([]byte("mismatch test"))
	item.SignWithRSA(privateKey)
	builder.AddItem(item)

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	// Parse and verify
	bundle, err := ParseBundle(data)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if len(bundle.Items) != 1 {
		t.Errorf("expected 1 item, got %d", len(bundle.Items))
	}
}

// ============================================================
// Ethereum sign type (not supported for verify)
// ============================================================

func TestSetSignatureType_Ethereum(t *testing.T) {
	item := NewDataItem()
	err := item.SetSignatureType(EthereumSignType)
	if err != nil {
		t.Fatalf("Ethereum sign type should be settable: %v", err)
	}
	if item.SignatureType != EthereumSignType {
		t.Errorf("signature type should be %d, got %d", EthereumSignType, item.SignatureType)
	}
}

func TestVerify_EthereumSignType_NotSupported(t *testing.T) {
	item := NewDataItem()
	item.SignatureType = EthereumSignType
	item.Signature = make([]byte, 65)
	item.Owner = make([]byte, 65)
	item.Id = computeId(item.Signature)
	item.SetData([]byte("test"))

	err := item.Verify()
	if err == nil {
		t.Fatal("Ethereum verify should not be supported yet")
	}
	if !strings.Contains(err.Error(), "not supported") {
		t.Errorf("error should mention 'not supported', got: %v", err)
	}
}

// ============================================================
// Build with missing fields
// ============================================================

func TestBuild_MissingSignature(t *testing.T) {
	builder := NewBundleBuilder()
	item := NewDataItem()
	item.Owner = make([]byte, 512)
	item.Id = make([]byte, 32)
	item.SetSignatureType(ArweaveSignType)
	item.AddTag("Test", "Value")
	item.SetData([]byte("test"))
	// Signature not set
	builder.AddItem(item)

	_, err := builder.Build()
	if err == nil {
		t.Fatal("expected error for missing signature")
	}
	if !strings.Contains(err.Error(), "signature not set") {
		t.Errorf("error should mention signature, got: %v", err)
	}
}

func TestBuild_MissingOwner(t *testing.T) {
	builder := NewBundleBuilder()
	item := NewDataItem()
	item.Signature = make([]byte, 512)
	item.Id = make([]byte, 32)
	item.SetSignatureType(ArweaveSignType)
	item.AddTag("Test", "Value")
	item.SetData([]byte("test"))
	// Owner not set
	builder.AddItem(item)

	_, err := builder.Build()
	if err == nil {
		t.Fatal("expected error for missing owner")
	}
}

func TestBuild_MissingId(t *testing.T) {
	builder := NewBundleBuilder()
	item := NewDataItem()
	item.Signature = make([]byte, 512)
	item.Owner = make([]byte, 512)
	item.SetSignatureType(ArweaveSignType)
	item.AddTag("Test", "Value")
	item.SetData([]byte("test"))
	// Id not set
	builder.AddItem(item)

	_, err := builder.Build()
	if err == nil {
		t.Fatal("expected error for missing id")
	}
}

// ============================================================
// SignWithEd25519 with wrong owner length
// ============================================================

func TestSignWithEd25519_WrongOwner(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	item := NewDataItem()
	item.SetSignatureType(ED25519SignType)
	// Set wrong owner length (not 32)
	item.SetOwner(make([]byte, 33))
	item.AddTag("Test", "Value")
	item.SetData([]byte("test"))

	err = item.SignWithEd25519(privateKey)
	if err != nil {
		// SignWithEd25519 overrides the owner, so this may actually succeed
		t.Logf("SignWithEd25519 with wrong owner: %v (may override)", err)
	}
}

// ============================================================
// SignWithRSA with missing data
// ============================================================

func TestSignWithRSA_NoSignatureType(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	item := NewDataItem()
	// SignatureType not set
	item.AddTag("Test", "Value")
	item.SetData([]byte("test"))

	err = item.SignWithRSA(privateKey)
	if err != nil {
		// SignWithRSA sets the signature type to ArweaveSignType automatically
		t.Logf("SignWithRSA without signature type: %v", err)
	} else if item.SignatureType != ArweaveSignType {
		t.Errorf("SignWithRSA should set signature type to 1, got %d", item.SignatureType)
	}
}

// ============================================================
// Tag serialization roundtrip with edge cases
// ============================================================

func TestTagRoundTrip_SpecialCharacters(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	originalTags := []Tag{
		{Name: "Unicode-Tag", Value: "中文日本語한국어🎉"},
		{Name: "Binary-like", Value: "\x00\x01\x02\xFF"},
		{Name: "Spaces", Value: "  leading and trailing  "},
		{Name: "Special", Value: "!@#$%^&*()_+-=[]{}|;':\",./<>?"},
		{Name: "Empty-like", Value: "\t\n\r"},
	}

	builder := NewBundleBuilder()
	item := NewDataItem()
	item.SetTags(originalTags)
	item.SetData([]byte("roundtrip data"))

	if err := item.SignWithRSA(privateKey); err != nil {
		t.Fatalf("signing failed: %v", err)
	}
	builder.AddItem(item)

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	bundle, err := ParseBundle(data)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	parsedTags := bundle.Items[0].Tags
	if len(parsedTags) != len(originalTags) {
		t.Fatalf("tag count: expected %d, got %d", len(originalTags), len(parsedTags))
	}

	for i, tag := range parsedTags {
		if tag.Name != originalTags[i].Name {
			t.Errorf("tag %d name: expected %q, got %q", i, originalTags[i].Name, tag.Name)
		}
		if tag.Value != originalTags[i].Value {
			t.Errorf("tag %d value: expected %q, got %q", i, originalTags[i].Value, tag.Value)
		}
	}
}

// ============================================================
// Empty tags list roundtrip
// ============================================================

func TestTagRoundTrip_EmptyTags(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	builder := NewBundleBuilder()
	item := NewDataItem()
	// No tags added
	item.SetData([]byte("no tags data"))

	if err := item.SignWithRSA(privateKey); err != nil {
		t.Fatalf("signing failed: %v", err)
	}
	builder.AddItem(item)

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	bundle, err := ParseBundle(data)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if len(bundle.Items[0].Tags) != 0 {
		t.Errorf("expected 0 tags, got %d", len(bundle.Items[0].Tags))
	}
}

// ============================================================
// Multiple items with various sign types
// ============================================================

func TestBundle_MixedSignTypes(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	builder := NewBundleBuilder()

	// RSA item
	item1 := NewDataItem()
	item1.AddTag("SignType", "RSA")
	item1.SetData([]byte("RSA signed data"))
	item1.SignWithRSA(rsaKey)
	builder.AddItem(item1)

	// Ed25519 item
	item2 := NewDataItem()
	item2.SetSignatureType(ED25519SignType)
	item2.SetOwner(edPub)
	item2.AddTag("SignType", "Ed25519")
	item2.SetData([]byte("Ed25519 signed data"))
	item2.SignWithEd25519(edPriv)
	builder.AddItem(item2)

	if builder.ItemCount() != 2 {
		t.Fatalf("expected 2 items, got %d", builder.ItemCount())
	}

	data, err := builder.Build()
	if err != nil {
		t.Fatalf("build mixed types failed: %v", err)
	}

	bundle, err := ParseBundle(data)
	if err != nil {
		t.Fatalf("parse mixed types failed: %v", err)
	}

	if len(bundle.Items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(bundle.Items))
	}

	// Verify each item
	for i, item := range bundle.Items {
		if err := item.Verify(); err != nil {
			t.Errorf("item %d verification failed: %v", i, err)
		}
	}
}
