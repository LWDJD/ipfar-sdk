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

	"github.com/LWDJD/ipfar-sdk/log"
)

// GatewayClient interacts with an Arweave gateway HTTP API.
type GatewayClient struct {
	GatewayURL string
	client     *http.Client
	userAgent  string
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
// If a User-Agent has been set via SetUserAgent, the transport of the
// new client will be wrapped to inject the User-Agent header.
func (gc *GatewayClient) SetHTTPClient(c *http.Client) {
	gc.client = c
	gc.ensureUserAgentTransport()
}

// HTTPClient returns the internal *http.Client.
func (gc *GatewayClient) HTTPClient() *http.Client {
	return gc.client
}

// SetUserAgent sets the User-Agent header for requests made by this client.
// It wraps the current transport with a User-Agent injecting round tripper.
func (gc *GatewayClient) SetUserAgent(ua string) {
	gc.userAgent = ua
	if gc.client.Transport == nil {
		gc.client.Transport = &userAgentTransport{
			next:      http.DefaultTransport,
			userAgent: ua,
		}
	} else if _, ok := gc.client.Transport.(*userAgentTransport); ok {
		gc.client.Transport.(*userAgentTransport).userAgent = ua
	} else {
		gc.client.Transport = &userAgentTransport{
			next:      gc.client.Transport,
			userAgent: ua,
		}
	}
}

// userAgentTransport wraps an http.RoundTripper and injects a User-Agent header.
type userAgentTransport struct {
	next      http.RoundTripper
	userAgent string
}

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.userAgent != "" && req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", t.userAgent)
	}
	return t.next.RoundTrip(req)
}

// ensureUserAgentTransport 如果 userAgent 已设置但 transport 尚未包装，则进行包装。
// 在 SetHTTPClient 被调用后需要调用此方法。
func (gc *GatewayClient) ensureUserAgentTransport() {
	if gc.userAgent == "" {
		return
	}
	if gc.client.Transport == nil {
		gc.client.Transport = &userAgentTransport{
			next:      http.DefaultTransport,
			userAgent: gc.userAgent,
		}
		return
	}
	if _, ok := gc.client.Transport.(*userAgentTransport); ok {
		return
	}
	gc.client.Transport = &userAgentTransport{
		next:      gc.client.Transport,
		userAgent: gc.userAgent,
	}
}

// =============================================================================
// Basic gateway endpoints
// =============================================================================

// CheckHealth checks the gateway's health by calling GET /info.
// Returns nil if the gateway responds with HTTP 200, or an error otherwise.
func (gc *GatewayClient) CheckHealth(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", gc.GatewayURL+"/info", nil)
	if err != nil {
		return fmt.Errorf("health check request failed: %w", err)
	}
	resp, err := gc.client.Do(req)
	if err != nil {
		return fmt.Errorf("health check failed for %s: %w", gc.GatewayURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check failed for %s: HTTP %d", gc.GatewayURL, resp.StatusCode)
	}
	return nil
}

// GetNetworkInfo retrieves current network information from GET /info.
// Returns the parsed info map including network height, version, etc.
func (gc *GatewayClient) GetNetworkInfo(ctx context.Context) (*NetworkInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", gc.GatewayURL+"/info", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	resp, err := gc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get network info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("gateway returned %d: %s", resp.StatusCode, string(body))
	}

	var info NetworkInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("failed to decode network info: %w", err)
	}
	return &info, nil
}

// NetworkInfo holds Arweave network information returned by GET /info.
type NetworkInfo struct {
	Network          string `json:"network"`
	Version          int    `json:"version"`
	Release          int    `json:"release"`
	Height           int64  `json:"height"`
	Current          string `json:"current"`
	Blocks           int64  `json:"blocks"`
	Peers            int    `json:"peers"`
	QueueLength      int    `json:"queue_length"`
	NodeStateLatency int64  `json:"node_state_latency"`
}

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

	log.Debug(ctx, "POST /tx (id=%s)", tx.ID)
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
	log.Debug(ctx, "GET /tx/%s/status", txID)
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

	contentTypeB64 := base64.RawURLEncoding.EncodeToString([]byte("application/vnd.ipld.car"))
	protocolB64 := base64.RawURLEncoding.EncodeToString([]byte("IPFS-Arweave-Bridge"))

	q := NewGraphQLQuery().
		AddTagFilter("Root-CID", rootCID).
		AddTagFilter("Content-Type", "application/vnd.ipld.car", contentTypeB64).
		AddTagFilter("Protocol", "IPFS-Arweave-Bridge", protocolB64).
		SetFirst(limit).
		SetSort("HEIGHT_DESC")

	return gc.RunGraphQL(ctx, q)
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

	rootCIDB64 := base64.RawURLEncoding.EncodeToString([]byte(rootCID))
	protocolB64 := base64.RawURLEncoding.EncodeToString([]byte("IPFS-Arweave-Bridge"))
	ipfarTypeB64 := base64.RawURLEncoding.EncodeToString([]byte("meta"))
	contentTypeB64 := base64.RawURLEncoding.EncodeToString([]byte("application/json"))

	q := NewGraphQLQuery().
		AddTagFilter("Root-CID", rootCID, rootCIDB64).
		AddTagFilter("Protocol", "IPFS-Arweave-Bridge", protocolB64).
		AddTagFilter("IPFAR-Type", "meta", ipfarTypeB64).
		AddTagFilter("Content-Type", "application/json", contentTypeB64).
		SetFirst(limit).
		SetSort("HEIGHT_DESC")

	if dataTXID != "" {
		dataTXIDB64 := base64.RawURLEncoding.EncodeToString([]byte(dataTXID))
		q.AddTagFilter("Data-TXID", dataTXID, dataTXIDB64)
	}

	return gc.RunGraphQL(ctx, q)
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

// GetTransactionTags fetches the tags of a transaction by its ID.
// Tags are returned in their decoded (plain-text) form.
func (gc *GatewayClient) GetTransactionTags(ctx context.Context, txID string) ([]Tag, error) {
	log.Debug(ctx, "GET /tx/%s (tags)", txID)
	req, err := http.NewRequestWithContext(ctx, "GET", gc.GatewayURL+"/tx/"+txID, nil)
	if err != nil {
		return nil, err
	}
	resp, err := gc.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gateway returned %d for tx %s", resp.StatusCode, txID)
	}

	var result struct {
		Tags []Tag `json:"tags"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode tx %s: %w", txID, err)
	}

	// Tags from gateway are base64url-encoded; decode them.
	decoded := make([]Tag, len(result.Tags))
	for i, t := range result.Tags {
		nameBytes, err := base64.RawURLEncoding.DecodeString(t.Name)
		if err != nil {
			nameBytes = []byte(t.Name)
		}
		valueBytes, err := base64.RawURLEncoding.DecodeString(t.Value)
		if err != nil {
			valueBytes = []byte(t.Value)
		}
		decoded[i] = Tag{Name: string(nameBytes), Value: string(valueBytes)}
	}
	return decoded, nil
}

// DownloadTransactionData downloads the full raw data of a transaction
// using GET /{txID}.  Returns the raw bytes of the transaction data.
func (gc *GatewayClient) DownloadTransactionData(ctx context.Context, txID string) ([]byte, error) {
	url := gc.GatewayURL + "/" + txID
	log.Debug(ctx, "GET %s", url)
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
