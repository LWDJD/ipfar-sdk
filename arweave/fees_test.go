package arweave

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// =============================================================================
// FeeEstimate tests
// =============================================================================

func TestEstimateFee_Mock(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/price/"):
			// Extract data size from URL and return a proportional reward.
			var size int64
			fmt.Sscanf(r.URL.Path, "/price/%d", &size)
			// 1 AR per MB = 1e12 winston per 1,048,576 bytes
			reward := int64(float64(size) / 1_048_576.0 * 1_000_000_000_000.0)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf("%d", reward)))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)

	// 1 MB of data
	est, err := client.EstimateFee(context.Background(), 1_048_576)
	if err != nil {
		t.Fatalf("EstimateFee failed: %v", err)
	}

	if est.DataSize != 1_048_576 {
		t.Errorf("expected DataSize 1048576, got %d", est.DataSize)
	}
	if est.RewardAR <= 0 {
		t.Error("RewardAR should be positive")
	}
	if est.DataPerAR <= 0 {
		t.Error("DataPerAR should be positive")
	}

	// With our mock, 1MB should cost ~1 AR.
	if est.RewardAR < 0.9 || est.RewardAR > 1.1 {
		t.Errorf("expected ~1 AR for 1 MB, got %f AR", est.RewardAR)
	}

	t.Logf("Size: %d bytes, Reward: %s winston, %.6f AR, %.0f bytes/AR",
		est.DataSize, est.Reward, est.RewardAR, est.DataPerAR)
}

func TestEstimateFee_SmallData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/price/") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("1000000")) // 1 million winston = tiny fraction of AR
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)

	est, err := client.EstimateFee(context.Background(), 100)
	if err != nil {
		t.Fatalf("EstimateFee failed: %v", err)
	}

	if est.DataSize != 100 {
		t.Errorf("expected DataSize 100, got %d", est.DataSize)
	}
	if est.Reward != "1000000" {
		t.Errorf("expected Reward '1000000', got %q", est.Reward)
	}

	// 1 million winston = 1e6 / 1e12 = 0.000001 AR
	expectedAR := 1_000_000.0 / 1_000_000_000_000.0
	if est.RewardAR != expectedAR {
		t.Errorf("expected RewardAR %f, got %f", expectedAR, est.RewardAR)
	}

	t.Logf("Reward: %s winston = %.10f AR", est.Reward, est.RewardAR)
}

func TestEstimateFee_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)

	_, err := client.EstimateFee(context.Background(), 1000)
	if err == nil {
		t.Fatal("expected error for server error")
	}
	t.Logf("Got expected error: %v", err)
}

func TestEstimateFee_EmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("")) // empty body
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)

	_, err := client.EstimateFee(context.Background(), 1000)
	if err == nil {
		t.Fatal("expected error for empty response")
	}
	t.Logf("Got expected error: %v", err)
}

func TestEstimateFee_InvalidResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not-a-number"))
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)

	_, err := client.EstimateFee(context.Background(), 1000)
	if err == nil {
		t.Fatal("expected error for invalid response")
	}
	t.Logf("Got expected error: %v", err)
}

func TestEstimateUploadFee_Overhead(t *testing.T) {
	// Track what data sizes are requested.
	var requestedSizes []int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/price/") {
			var size int64
			fmt.Sscanf(r.URL.Path, "/price/%d", &size)
			requestedSizes = append(requestedSizes, size)

			// Return reward: 1 winston per 10 bytes (simple).
			reward := size / 10
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf("%d", reward)))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)

	fileSize := int64(1_000_000) // 1 MB file
	est, err := client.EstimateUploadFee(context.Background(), fileSize)
	if err != nil {
		t.Fatalf("EstimateUploadFee failed: %v", err)
	}

	// The total size should include CAR overhead + metadata overhead.
	expectedTotal := fileSize + CarHeaderOverhead + MetadataTxOverhead
	if est.DataSize != expectedTotal {
		t.Errorf("expected DataSize %d (file %d + CAR %d + meta %d), got %d",
			expectedTotal, fileSize, CarHeaderOverhead, MetadataTxOverhead, est.DataSize)
	}

	// The requested size should match.
	if len(requestedSizes) == 1 && requestedSizes[0] != expectedTotal {
		t.Errorf("expected /price/%d request, got /price/%d", expectedTotal, requestedSizes[0])
	}

	t.Logf("File size: %d, total upload size: %d, reward: %s winston (%.6f AR)",
		fileSize, est.DataSize, est.Reward, est.RewardAR)
}

func TestEstimateUploadFee_SmallFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/price/") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("500"))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)

	// Very small file (10 bytes).
	est, err := client.EstimateUploadFee(context.Background(), 10)
	if err != nil {
		t.Fatalf("EstimateUploadFee failed: %v", err)
	}

	expectedTotal := int64(10) + CarHeaderOverhead + MetadataTxOverhead
	if est.DataSize != expectedTotal {
		t.Errorf("expected DataSize %d, got %d", expectedTotal, est.DataSize)
	}
	if est.Reward != "500" {
		t.Errorf("expected Reward '500', got %q", est.Reward)
	}

	t.Logf("Small file (10 bytes) total estimate: %d bytes → %s winston", est.DataSize, est.Reward)
}

func TestEstimateUploadFee_LargeFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/price/") {
			var size int64
			fmt.Sscanf(r.URL.Path, "/price/%d", &size)
			// 1 winston per byte (simple mock).
			reward := size
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf("%d", reward)))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewGatewayClient(server.URL)

	// 100 MB file.
	fileSize := int64(100 * 1024 * 1024)
	est, err := client.EstimateUploadFee(context.Background(), fileSize)
	if err != nil {
		t.Fatalf("EstimateUploadFee failed: %v", err)
	}

	expectedTotal := fileSize + CarHeaderOverhead + MetadataTxOverhead
	if est.DataSize != expectedTotal {
		t.Errorf("expected DataSize %d, got %d", expectedTotal, est.DataSize)
	}

	// Overhead should be negligible for large files.
	overheadRatio := float64(CarHeaderOverhead+MetadataTxOverhead) / float64(fileSize)
	if overheadRatio > 0.01 {
		t.Logf("overhead ratio for 100 MB file: %.6f (should be tiny)", overheadRatio)
	}

	t.Logf("Large file: %d bytes → total %d bytes (overhead %.4f%%), reward: %.6f AR",
		fileSize, est.DataSize, overheadRatio*100, est.RewardAR)
}

// =============================================================================
// buildFeeEstimate edge cases
// =============================================================================

func TestBuildFeeEstimate_ZeroReward(t *testing.T) {
	est, err := buildFeeEstimate(100, "0")
	if err != nil {
		t.Fatalf("buildFeeEstimate should not error on '0': %v", err)
	}
	if est.RewardAR != 0 {
		t.Errorf("expected 0 RewardAR, got %f", est.RewardAR)
	}
	if est.DataPerAR != 0 {
		t.Errorf("expected 0 DataPerAR when reward is 0, got %f", est.DataPerAR)
	}
}

func TestBuildFeeEstimate_LargeWinston(t *testing.T) {
	// 10 AR = 10 * 1e12 winston
	est, err := buildFeeEstimate(10_485_760, "10000000000000")
	if err != nil {
		t.Fatalf("buildFeeEstimate failed: %v", err)
	}
	if est.RewardAR != 10.0 {
		t.Errorf("expected 10.0 AR, got %f", est.RewardAR)
	}
	// 10 MB for 10 AR = 1 MB/AR
	expectedBytesPerAR := float64(10_485_760) / 10.0
	if est.DataPerAR != expectedBytesPerAR {
		t.Errorf("expected DataPerAR %f, got %f", expectedBytesPerAR, est.DataPerAR)
	}
}

// =============================================================================
// Constants sanity
// =============================================================================

func TestWinstonPerAR(t *testing.T) {
	if WinstonPerAR != 1_000_000_000_000 {
		t.Errorf("WinstonPerAR should be 1_000_000_000_000, got %d", WinstonPerAR)
	}
}

func TestOverheadConstants(t *testing.T) {
	if CarHeaderOverhead <= 0 {
		t.Error("CarHeaderOverhead should be positive")
	}
	if MetadataTxOverhead <= 0 {
		t.Error("MetadataTxOverhead should be positive")
	}
}
