package arweave

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// GatewayClient interacts with an Arweave gateway HTTP API.
type GatewayClient struct {
	GatewayURL string
	client     *http.Client
}

// NewGatewayClient creates a new GatewayClient for the given gateway URL.
func NewGatewayClient(gatewayURL string) *GatewayClient {
	return &GatewayClient{
		GatewayURL: strings.TrimRight(gatewayURL, "/"),
		client: &http.Client{
			Timeout: 300 * time.Second,
		},
	}
}

// SetHTTPClient replaces the internal *http.Client (e.g. for tests).
func (gc *GatewayClient) SetHTTPClient(c *http.Client) {
	gc.client = c
}

// HTTPClient returns the internal *http.Client.
func (gc *GatewayClient) HTTPClient() *http.Client {
	return gc.client
}

// =============================================================================
// Basic gateway endpoints
// =============================================================================

// GetAnchor retrieves a recent transaction anchor from the gateway.
func (gc *GatewayClient) GetAnchor(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", gc.GatewayURL+"/tx_anchor", nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	resp, err := gc.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get anchor: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	// The response is a JSON string like `"<txid>"`; trim quotes.
	return strings.Trim(string(body), "\""), nil
}

// GetReward fetches the recommended mining reward (in Winston) for the given
// data size in bytes.
func (gc *GatewayClient) GetReward(ctx context.Context, dataSize int64) (string, error) {
	url := fmt.Sprintf("%s/price/%d", gc.GatewayURL, dataSize)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	resp, err := gc.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get price: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

// SubmitTransaction posts a signed transaction to the gateway.
// Returns the transaction ID.
func (gc *GatewayClient) SubmitTransaction(ctx context.Context, tx *Transaction) (string, error) {
	body, err := tx.ToJSON()
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", gc.GatewayURL+"/tx", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := gc.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to submit tx: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return "", fmt.Errorf("gateway returned %d: %s", resp.StatusCode, string(respBody))
	}

	return tx.ID, nil
}

// =============================================================================
// Transaction status
// =============================================================================

// TransactionStatus reports the confirmation state of a transaction.
type TransactionStatus struct {
	Confirmed   bool
	BlockHeight int
	BlockHash   string
}

// GetTransactionStatus checks whether a transaction is confirmed.
func (gc *GatewayClient) GetTransactionStatus(ctx context.Context, txID string) (*TransactionStatus, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", gc.GatewayURL+"/tx/"+txID+"/status", nil)
	if err != nil {
		return nil, err
	}
	resp, err := gc.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusAccepted {
		return &TransactionStatus{Confirmed: false}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return &TransactionStatus{Confirmed: false}, nil
	}

	var result struct {
		BlockHeight           int    `json:"block_height"`
		BlockIndepHash        string `json:"block_indep_hash"`
		NumberOfConfirmations int    `json:"number_of_confirmations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &TransactionStatus{
		Confirmed:   result.BlockHeight > 0,
		BlockHeight: result.BlockHeight,
		BlockHash:   result.BlockIndepHash,
	}, nil
}

// GetTransactionDataSize fetches the data_size field from GET /tx/{txID}.
func (gc *GatewayClient) GetTransactionDataSize(ctx context.Context, txID string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", gc.GatewayURL+"/tx/"+txID, nil)
	if err != nil {
		return 0, err
	}
	resp, err := gc.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("gateway returned %d for tx %s", resp.StatusCode, txID)
	}

	var result struct {
		DataSize string `json:"data_size"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("failed to decode tx %s: %w", txID, err)
	}

	size, err := strconv.ParseInt(result.DataSize, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid data_size for tx %s: %w", txID, err)
	}
	if size <= 0 {
		return 0, fmt.Errorf("data_size not available for tx %s", txID)
	}
	return size, nil
}

// WaitForConfirmation polls the gateway until the transaction is confirmed
// or the context is cancelled.  maxAttempts × pollInterval defines the
// maximum wait time.
func (gc *GatewayClient) WaitForConfirmation(ctx context.Context, txID string, maxAttempts int, pollInterval time.Duration) (*TransactionStatus, error) {
	for i := 0; i < maxAttempts; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		status, err := gc.GetTransactionStatus(ctx, txID)
		if err == nil && status.Confirmed && status.BlockHeight > 0 {
			return status, nil
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(pollInterval):
		}
	}
	return nil, fmt.Errorf("transaction %s not confirmed after %d attempts", txID, maxAttempts)
}

// =============================================================================
// GraphQL queries
// =============================================================================

// gqlResp is a minimal GraphQL response envelope.
type gqlResp struct {
	Data struct {
		Transactions struct {
			Edges []struct {
				Node struct {
					ID string `json:"id"`
				} `json:"node"`
			} `json:"edges"`
		} `json:"transactions"`
	} `json:"data"`
}

// QueryExistingCARs queries the Arweave GraphQL endpoint for transactions
// tagged with the given Root-CID, Protocol "IPFS-Arweave-Bridge", and
// Content-Type "application/vnd.ipld.car".  Results are sorted by block
// height descending.  Returns up to limit transaction IDs.
//
// Tag values are matched in both plain-text and base64url-encoded forms
// to handle both legacy plain-text tags and goar chunked-upload tags.
func (gc *GatewayClient) QueryExistingCARs(ctx context.Context, rootCID string, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 8
	}

	protocolB64 := base64.RawURLEncoding.EncodeToString([]byte("IPFS-Arweave-Bridge"))
	contentTypeB64 := base64.RawURLEncoding.EncodeToString([]byte("application/vnd.ipld.car"))

	query := fmt.Sprintf(`{
		transactions(
			tags: [
				{ name: "Root-CID", values: ["%s"] },
				{ name: "Content-Type", values: ["application/vnd.ipld.car", "%s"] },
				{ name: "Protocol", values: ["IPFS-Arweave-Bridge", "%s"] }
			],
			first: %d,
			sort: HEIGHT_DESC
		) {
			edges {
				node { id }
			}
		}
	}`, rootCID, contentTypeB64, protocolB64, limit)

	return gc.runGraphQLQuery(ctx, query)
}

// QueryExistingMetas queries the Arweave GraphQL endpoint for metadata
// transactions tagged with the given Root-CID, Protocol "IPFS-Arweave-Bridge",
// IPFAR-Type "meta", and Content-Type "application/json".  Optionally filters
// by Data-TXID.  Returns up to limit transaction IDs.
//
// Tag values are matched in both plain-text and base64url-encoded forms.
func (gc *GatewayClient) QueryExistingMetas(ctx context.Context, rootCID, dataTXID string, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 8
	}

	protocolB64 := base64.RawURLEncoding.EncodeToString([]byte("IPFS-Arweave-Bridge"))
	ipfarTypeB64 := base64.RawURLEncoding.EncodeToString([]byte("meta"))
	contentTypeB64 := base64.RawURLEncoding.EncodeToString([]byte("application/json"))
	rootCIDB64 := base64.RawURLEncoding.EncodeToString([]byte(rootCID))

	tagsQuery := fmt.Sprintf(`
		{ name: "Root-CID", values: ["%s", "%s"] },
		{ name: "Protocol", values: ["IPFS-Arweave-Bridge", "%s"] },
		{ name: "IPFAR-Type", values: ["meta", "%s"] },
		{ name: "Content-Type", values: ["application/json", "%s"] }`,
		rootCID, rootCIDB64, protocolB64, ipfarTypeB64, contentTypeB64)

	if dataTXID != "" {
		dataTXIDB64 := base64.RawURLEncoding.EncodeToString([]byte(dataTXID))
		tagsQuery += fmt.Sprintf(`,
		{ name: "Data-TXID", values: ["%s", "%s"] }`, dataTXID, dataTXIDB64)
	}

	query := fmt.Sprintf(`{
		transactions(
			tags: [%s],
			first: %d,
			sort: HEIGHT_DESC
		) {
			edges {
				node { id }
			}
		}
	}`, tagsQuery, limit)

	return gc.runGraphQLQuery(ctx, query)
}

// runGraphQLQuery executes a GraphQL query and returns matching transaction IDs.
func (gc *GatewayClient) runGraphQLQuery(ctx context.Context, query string) ([]string, error) {
	payload := map[string]string{"query": query}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal GraphQL query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", gc.GatewayURL+"/graphql", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("GraphQL query failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := gc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GraphQL query failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GraphQL returned %d: %s", resp.StatusCode, string(respBody))
	}

	var gqlResp gqlResp
	if err := json.Unmarshal(respBody, &gqlResp); err != nil {
		return nil, fmt.Errorf("failed to parse GraphQL response: %w", err)
	}

	ids := make([]string, 0, len(gqlResp.Data.Transactions.Edges))
	for _, e := range gqlResp.Data.Transactions.Edges {
		if e.Node.ID != "" {
			ids = append(ids, e.Node.ID)
		}
	}
	return ids, nil
}

// DownloadTransactionData downloads the full raw data of a transaction
// using GET /{txID}.  Returns the raw bytes of the transaction data.
func (gc *GatewayClient) DownloadTransactionData(ctx context.Context, txID string) ([]byte, error) {
	url := gc.GatewayURL + "/" + txID
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := gc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download tx %s: %w", txID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("gateway returned %d for tx %s: %s", resp.StatusCode, txID, string(body))
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body for tx %s: %w", txID, err)
	}

	return data, nil
}
