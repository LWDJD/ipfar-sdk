package arweave

import (
	"context"
	"io"
	"net/http"
	"sync"
	"time"
)

// MultiGatewayClient wraps multiple GatewayClient instances with automatic
// failover and health checking.  Implements the same core API as GatewayClient.
type MultiGatewayClient struct {
	gateways []*GatewayClient
	current  int
	mu       sync.Mutex
}

// NewMultiGatewayClient creates a client with the given gateway URLs.
// The first URL is the primary; subsequent URLs are fallbacks.
func NewMultiGatewayClient(urls ...string) *MultiGatewayClient {
	gateways := make([]*GatewayClient, len(urls))
	for i, u := range urls {
		gateways[i] = NewGatewayClient(u)
	}
	return &MultiGatewayClient{
		gateways: gateways,
		current:  0,
	}
}

// SetHTTPClient sets a custom HTTP client on all underlying gateway clients.
// This allows injecting proxy-configured clients for bridge-specific features
// like SOCKS5 support.
func (m *MultiGatewayClient) SetHTTPClient(c *http.Client) {
	for _, gw := range m.gateways {
		gw.SetHTTPClient(c)
	}
}

// SetUserAgent sets the User-Agent header on all underlying gateway clients.
func (m *MultiGatewayClient) SetUserAgent(ua string) {
	for _, gw := range m.gateways {
		gw.SetUserAgent(ua)
	}
}

// Do attempts a request across all gateways, returning the first success.
// On failure, it advances to the next gateway (round-robin).
func (m *MultiGatewayClient) Do(ctx context.Context, fn func(gw *GatewayClient) error) error {
	// Check context before starting.
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	start := m.getCurrent()
	num := len(m.gateways)
	if num == 0 {
		return io.ErrNoProgress
	}

	var lastErr error
	for i := 0; i < num; i++ {
		idx := (start + i) % num
		gw := m.gateways[idx]

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		err := fn(gw)
		if err == nil {
			// Success — keep this gateway as current for future calls.
			m.setCurrent(idx)
			return nil
		}
		lastErr = err
	}

	return lastErr
}

// getCurrent returns the current gateway index in a thread-safe way.
func (m *MultiGatewayClient) getCurrent() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current
}

// setCurrent sets the current gateway index in a thread-safe way.
func (m *MultiGatewayClient) setCurrent(idx int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.current = idx
}

// =============================================================================
// Wrapped GatewayClient methods
// =============================================================================

// GetTransactionStatus checks transaction status across all gateways.
func (m *MultiGatewayClient) GetTransactionStatus(ctx context.Context, txID string) (*TransactionStatus, error) {
	var result *TransactionStatus
	err := m.Do(ctx, func(gw *GatewayClient) error {
		var e error
		result, e = gw.GetTransactionStatus(ctx, txID)
		return e
	})
	return result, err
}

// GetTransactionDataSize fetches the data size across all gateways.
func (m *MultiGatewayClient) GetTransactionDataSize(ctx context.Context, txID string) (int64, error) {
	var result int64
	err := m.Do(ctx, func(gw *GatewayClient) error {
		var e error
		result, e = gw.GetTransactionDataSize(ctx, txID)
		return e
	})
	return result, err
}

// DownloadTransactionData downloads transaction data across all gateways.
func (m *MultiGatewayClient) DownloadTransactionData(ctx context.Context, txID string) ([]byte, error) {
	var result []byte
	err := m.Do(ctx, func(gw *GatewayClient) error {
		var e error
		result, e = gw.DownloadTransactionData(ctx, txID)
		return e
	})
	return result, err
}

// DownloadTransactionToWriter streams transaction data to a writer across all gateways.
func (m *MultiGatewayClient) DownloadTransactionToWriter(ctx context.Context, txID string, w io.Writer) (int64, error) {
	var result int64
	err := m.Do(ctx, func(gw *GatewayClient) error {
		var e error
		result, e = gw.DownloadTransactionToWriter(ctx, txID, w)
		return e
	})
	return result, err
}

// DownloadTransactionRange downloads a byte range across all gateways.
func (m *MultiGatewayClient) DownloadTransactionRange(ctx context.Context, txID string, offset, length int64) ([]byte, error) {
	var result []byte
	err := m.Do(ctx, func(gw *GatewayClient) error {
		var e error
		result, e = gw.DownloadTransactionRange(ctx, txID, offset, length)
		return e
	})
	return result, err
}

// WaitForConfirmation polls for confirmation across all gateways.
func (m *MultiGatewayClient) WaitForConfirmation(ctx context.Context, txID string, maxAttempts int, pollInterval time.Duration) (*TransactionStatus, error) {
	var result *TransactionStatus
	err := m.Do(ctx, func(gw *GatewayClient) error {
		var e error
		result, e = gw.WaitForConfirmation(ctx, txID, maxAttempts, pollInterval)
		return e
	})
	return result, err
}

// QueryExistingCARs queries for existing CARs across all gateways.
func (m *MultiGatewayClient) QueryExistingCARs(ctx context.Context, rootCID string, limit int) ([]string, error) {
	var result []string
	err := m.Do(ctx, func(gw *GatewayClient) error {
		var e error
		result, e = gw.QueryExistingCARs(ctx, rootCID, limit)
		return e
	})
	return result, err
}

// QueryExistingMetas queries for existing meta transactions across all gateways.
func (m *MultiGatewayClient) QueryExistingMetas(ctx context.Context, rootCID, dataTXID string, limit int) ([]string, error) {
	var result []string
	err := m.Do(ctx, func(gw *GatewayClient) error {
		var e error
		result, e = gw.QueryExistingMetas(ctx, rootCID, dataTXID, limit)
		return e
	})
	return result, err
}

// RunGraphQL executes a GraphQL query across all gateways.
func (m *MultiGatewayClient) RunGraphQL(ctx context.Context, query *GraphQLQuery) ([]string, error) {
	var result []string
	err := m.Do(ctx, func(gw *GatewayClient) error {
		var e error
		result, e = gw.RunGraphQL(ctx, query)
		return e
	})
	return result, err
}

// EstimateFee estimates the upload fee across all gateways.
func (m *MultiGatewayClient) EstimateFee(ctx context.Context, dataSize int64) (*FeeEstimate, error) {
	var result *FeeEstimate
	err := m.Do(ctx, func(gw *GatewayClient) error {
		var e error
		result, e = gw.EstimateFee(ctx, dataSize)
		return e
	})
	return result, err
}

// EstimateUploadFee estimates the total upload fee across all gateways.
func (m *MultiGatewayClient) EstimateUploadFee(ctx context.Context, fileSize int64) (*FeeEstimate, error) {
	var result *FeeEstimate
	err := m.Do(ctx, func(gw *GatewayClient) error {
		var e error
		result, e = gw.EstimateUploadFee(ctx, fileSize)
		return e
	})
	return result, err
}

// FetchBundleItemByID fetches a bundle item by ID across all gateways.
func (m *MultiGatewayClient) FetchBundleItemByID(ctx context.Context, bundleTXID, itemID string) ([]byte, error) {
	var result []byte
	err := m.Do(ctx, func(gw *GatewayClient) error {
		var e error
		result, e = gw.FetchBundleItemByID(ctx, bundleTXID, itemID)
		return e
	})
	return result, err
}

// GetNetworkInfo retrieves network information across all gateways.
func (m *MultiGatewayClient) GetNetworkInfo(ctx context.Context) (*NetworkInfo, error) {
	var result *NetworkInfo
	err := m.Do(ctx, func(gw *GatewayClient) error {
		var e error
		result, e = gw.GetNetworkInfo(ctx)
		return e
	})
	return result, err
}

// CheckHealth checks the health of all gateways by calling GET /info.
// Returns the first successful gateway's health check or the last error.
func (m *MultiGatewayClient) CheckHealth(ctx context.Context) error {
	return m.Do(ctx, func(gw *GatewayClient) error {
		return gw.CheckHealth(ctx)
	})
}
