// Package arweave provides a minimal stub for Arweave gateway interaction.
// The full implementation will be added by another agent.
package arweave

import (
	"context"
	"crypto/rsa"
)

// ── Constants ──────────────────────────────────────────────────────────

// ChunkSize is the default Arweave data chunk size (256 KiB).
const ChunkSize = 256 * 1024

// ── Tag ────────────────────────────────────────────────────────────────

// Tag represents an Arweave transaction tag (name-value pair).
type Tag struct {
	Name  string
	Value string
}

// ── Wallet ─────────────────────────────────────────────────────────────

// Wallet holds an Arweave RSA key pair and derived fields.
type Wallet struct {
	PrivateKey *rsa.PrivateKey
	Owner      string // Base64URL of modulus bytes
	Address    string // Base64URL of SHA-256 of modulus bytes
}

// ── Transaction ────────────────────────────────────────────────────────

// Transaction represents a signed Arweave transaction.
type Transaction struct {
	ID string
}

// TransactionStatus represents confirmation status from the gateway.
type TransactionStatus struct {
	Confirmed   bool
	BlockHeight int
}

// ── GatewayClient ──────────────────────────────────────────────────────

// GatewayClient interacts with an Arweave gateway.
type GatewayClient struct {
	GatewayURL string
}

// NewGatewayClient creates a new GatewayClient for the given gateway URL.
func NewGatewayClient(gatewayURL string) *GatewayClient {
	return &GatewayClient{GatewayURL: gatewayURL}
}

// UploadDataChunked uploads data using the chunked upload endpoint (goar).
// Returns the transaction and its confirmation status.
func (gc *GatewayClient) UploadDataChunked(ctx context.Context, wallet *Wallet, data []byte, tags []Tag) (*Transaction, *TransactionStatus, error) {
	// Stub — real implementation coming in another agent
	return nil, nil, nil
}

// DownloadTransactionData downloads the full raw data of a transaction.
func (gc *GatewayClient) DownloadTransactionData(ctx context.Context, txID string) ([]byte, error) {
	// Stub — real implementation coming in another agent
	return nil, nil
}

// GetTransactionStatus checks whether a transaction is confirmed.
func (gc *GatewayClient) GetTransactionStatus(ctx context.Context, txID string) (*TransactionStatus, error) {
	// Stub — real implementation coming in another agent
	return nil, nil
}

// GetTransactionDataSize fetches the data_size field from /tx/{txID}.
func (gc *GatewayClient) GetTransactionDataSize(ctx context.Context, txID string) (int64, error) {
	// Stub — real implementation coming in another agent
	return 0, nil
}

// QueryExistingCARs queries GraphQL for existing CAR transactions by Root-CID.
// Returns up to limit candidate transaction IDs.
func (gc *GatewayClient) QueryExistingCARs(ctx context.Context, rootCID string, limit int) ([]string, error) {
	// Stub — real implementation coming in another agent
	return nil, nil
}

// QueryExistingMetas queries GraphQL for existing metadata transactions
// matching the given rootCID and optional dataTXID.
func (gc *GatewayClient) QueryExistingMetas(ctx context.Context, rootCID, dataTXID string, limit int) ([]string, error) {
	// Stub — real implementation coming in another agent
	return nil, nil
}

// ── Bundle stubs ───────────────────────────────────────────────────────

// BundleItem represents a single item in an ANS-104 bundle.
type BundleItem struct {
	SignatureType int
	Signature     []byte
	Owner         []byte
	Target        []byte
	Anchor        []byte
	Tags          []Tag
	Data          []byte
	ID            []byte
	HasTarget     bool
	HasAnchor     bool
}

// BundleBuilder builds ANS-104 bundles.
type BundleBuilder struct{}

// NewBundleBuilder creates a new bundle builder.
func NewBundleBuilder() *BundleBuilder {
	return &BundleBuilder{}
}

// SignBundleItem signs a bundle item with the wallet.
func SignBundleItem(data []byte, tags []Tag, wallet *Wallet, anchor []byte) (*BundleItem, error) {
	// Stub — real implementation coming in another agent
	return nil, nil
}
