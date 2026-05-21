package arweave

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	arweaveverify "github.com/LWDJD/ipfar-sdk/verify/arweave"
)

// =============================================================================
// Streaming download
// =============================================================================

// DownloadTransactionToWriter streams transaction data to the given writer.
// It reads from GET /{txID} in 32KB chunks and writes them to w without
// buffering the entire transaction in memory.
// Returns the number of bytes written.
func (gc *GatewayClient) DownloadTransactionToWriter(ctx context.Context, txID string, w io.Writer) (int64, error) {
	url := gc.GatewayURL + "/" + txID
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := gc.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("failed to download tx %s: %w", txID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		body, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("gateway returned %d for tx %s: %s", resp.StatusCode, txID, string(body))
	}

	return io.CopyBuffer(w, resp.Body, make([]byte, 32*1024))
}

// DownloadTransactionRange downloads a byte range of transaction data using
// an HTTP Range request.  offset is inclusive, length is the number of bytes.
// The Range header is: bytes={offset}-{offset+length-1}.
func (gc *GatewayClient) DownloadTransactionRange(ctx context.Context, txID string, offset, length int64) ([]byte, error) {
	if offset < 0 {
		return nil, fmt.Errorf("offset must be non-negative")
	}
	if length <= 0 {
		return nil, fmt.Errorf("length must be positive")
	}

	url := gc.GatewayURL + "/" + txID
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	rangeValue := fmt.Sprintf("bytes=%d-%d", offset, offset+length-1)
	req.Header.Set("Range", rangeValue)

	resp, err := gc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download range for tx %s: %w", txID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("gateway returned %d for tx %s range request: %s", resp.StatusCode, txID, string(body))
	}

	// If the server returns OK instead of PartialContent, it may have ignored
	// the Range header. Discard offset bytes, then read up to length bytes.
	if resp.StatusCode == http.StatusOK {
		// Skip the first 'offset' bytes.
		if offset > 0 {
			discarded, err := io.CopyN(io.Discard, resp.Body, offset)
			if err != nil {
				return nil, fmt.Errorf("failed to skip offset bytes for tx %s: %w", txID, err)
			}
			if discarded < offset {
				return nil, fmt.Errorf("unexpected EOF while skipping offset for tx %s", txID)
			}
		}
		buf := make([]byte, length)
		n, err := io.ReadFull(resp.Body, buf)
		if err != nil && err != io.ErrUnexpectedEOF {
			return nil, fmt.Errorf("failed to read response body for tx %s range: %w", txID, err)
		}
		return buf[:n], nil
	}

	// For 206 Partial Content, read the exact range returned.
	// Parse Content-Range to get actual length.
	contentRange := resp.Header.Get("Content-Range")
	if contentRange != "" {
		// Content-Range: bytes {start}-{end}/{total}
		parts := strings.SplitN(contentRange, "/", 2)
		if len(parts) == 2 {
			rangeParts := strings.SplitN(parts[0], " ", 2)
			if len(rangeParts) == 2 {
				bounds := strings.SplitN(rangeParts[1], "-", 2)
				if len(bounds) == 2 {
					start, _ := strconv.ParseInt(bounds[0], 10, 64)
					end, _ := strconv.ParseInt(bounds[1], 10, 64)
					actualLength := end - start + 1
					buf := make([]byte, actualLength)
					_, err := io.ReadFull(resp.Body, buf)
					if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
						return nil, fmt.Errorf("failed to read range body for tx %s: %w", txID, err)
					}
					return buf, nil
				}
			}
		}
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body for tx %s range: %w", txID, err)
	}
	return data, nil
}

// =============================================================================
// Bundle item extraction (uses verify/arweave for parsing)
// =============================================================================

// FetchBundleItemByID downloads a bundle transaction from the gateway, parses
// its ANS-104 header, finds the item with the given base64url-encoded item ID,
// and returns the item's raw data bytes.
//
// This is a convenience method that combines DownloadTransactionToWriter with
// verify/arweave bundle parsing.  For large bundles, the header is downloaded
// first using a Range request, then the specific item is fetched via Range.
func (gc *GatewayClient) FetchBundleItemByID(ctx context.Context, bundleTXID, itemID string) ([]byte, error) {
	// First, download just the bundle header to find the item.
	url := gc.GatewayURL + "/" + bundleTXID

	// Fetch first 32 bytes to get item count.
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Range", "bytes=0-31")

	resp, err := gc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch bundle header: %w", err)
	}

	if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("gateway returned %d for bundle %s", resp.StatusCode, bundleTXID)
	}

	itemsNumBy := make([]byte, 32)
	_, err = io.ReadFull(resp.Body, itemsNumBy)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to read bundle item count: %w", err)
	}

	itemsNum := arweaveverify.ByteArrayToLong(itemsNumBy)
	if itemsNum <= 0 {
		return nil, fmt.Errorf("bundle %s has no items", bundleTXID)
	}

	// Read full header: 32 + itemsNum * 64 bytes.
	headerSize := 32 + itemsNum*64

	req2, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req2.Header.Set("Range", fmt.Sprintf("bytes=0-%d", headerSize-1))

	resp2, err := gc.client.Do(req2)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch full bundle header: %w", err)
	}

	if resp2.StatusCode != http.StatusPartialContent && resp2.StatusCode != http.StatusOK {
		resp2.Body.Close()
		return nil, fmt.Errorf("gateway returned %d for bundle header %s", resp2.StatusCode, bundleTXID)
	}

	headerData := make([]byte, headerSize)
	_, err = io.ReadFull(resp2.Body, headerData)
	resp2.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to read bundle header data: %w", err)
	}

	// Parse header to find item index by ID.
	var foundIndex int = -1
	var foundLength int
	var foundOffset int

	currentOffset := headerSize
	for i := 0; i < itemsNum; i++ {
		headerBegin := 32 + i*64
		itemBinaryLength := arweaveverify.ByteArrayToLong(headerData[headerBegin : headerBegin+32])
		itemHeaderID := headerData[headerBegin+32 : headerBegin+64]

		// Compare IDs: itemHeaderID is raw bytes, itemID is base64url-encoded.
		itemIDBase64 := arweaveverify.Base64Encode(itemHeaderID)
		if itemIDBase64 == itemID {
			foundIndex = i
			foundLength = itemBinaryLength
			foundOffset = currentOffset
			break
		}

		currentOffset += itemBinaryLength
	}

	if foundIndex < 0 {
		return nil, fmt.Errorf("item %s not found in bundle %s", itemID, bundleTXID)
	}

	// Now fetch the specific item data using Range request.
	req3, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req3.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", foundOffset, foundOffset+foundLength-1))

	resp3, err := gc.client.Do(req3)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch bundle item %d: %w", foundIndex, err)
	}
	defer resp3.Body.Close()

	if resp3.StatusCode != http.StatusPartialContent && resp3.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gateway returned %d for bundle item %d", resp3.StatusCode, foundIndex)
	}

	itemBinary := make([]byte, foundLength)
	_, err = io.ReadFull(resp3.Body, itemBinary)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, fmt.Errorf("failed to read bundle item data: %w", err)
	}

	// Decode the bundle item to extract its data.
	item, err := arweaveverify.DecodeBundleItem(itemBinary)
	if err != nil {
		return nil, fmt.Errorf("failed to decode bundle item: %w", err)
	}

	return arweaveverify.ExtractBundleItemData(&item)
}
