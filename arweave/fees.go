package arweave

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// =============================================================================
// Overhead constants for fee estimation
// =============================================================================

const (
	// CarHeaderOverhead estimates the CAR v2 header overhead in bytes.
	// A typical CAR v2 file adds ~200 bytes of framing (pragma, v2 header,
	// v1 header, block encoding varints, and CBOR index) around the raw data.
	CarHeaderOverhead = 200

	// MetadataTxOverhead estimates the size of an IPFAR metadata transaction
	// (JSON body with tags) in bytes.
	MetadataTxOverhead = 500

	// WinstonPerAR is the number of winston in 1 AR.
	WinstonPerAR = 1_000_000_000_000
)

// =============================================================================
// FeeEstimate
// =============================================================================

// FeeEstimate holds a cost estimate for uploading data to Arweave.
type FeeEstimate struct {
	DataSize  int64   // bytes
	Reward    string  // winston (as string, from gateway)
	RewardAR  float64 // converted to AR
	DataPerAR float64 // bytes per AR (helpful for comparison)
}

// =============================================================================
// Public API
// =============================================================================

// EstimateFee estimates the upload fee for the given data size by querying
// the gateway's /price/{dataSize} endpoint.
func (gc *GatewayClient) EstimateFee(ctx context.Context, dataSize int64) (*FeeEstimate, error) {
	rewardStr, err := gc.GetReward(ctx, dataSize)
	if err != nil {
		return nil, fmt.Errorf("failed to get reward for %d bytes: %w", dataSize, err)
	}

	return buildFeeEstimate(dataSize, rewardStr)
}

// EstimateUploadFee estimates the total fee for uploading a file of the given
// size, including both CAR file overhead and metadata transaction overhead.
func (gc *GatewayClient) EstimateUploadFee(ctx context.Context, fileSize int64) (*FeeEstimate, error) {
	// CAR file size = raw data + CAR header overhead.
	carSize := fileSize + CarHeaderOverhead

	// Metadata transaction size is roughly constant.
	metaSize := int64(MetadataTxOverhead)

	// Total bytes that will be uploaded to Arweave.
	totalSize := carSize + metaSize

	return gc.EstimateFee(ctx, totalSize)
}

// =============================================================================
// Internal helpers
// =============================================================================

// buildFeeEstimate parses a winston reward string and builds a FeeEstimate.
func buildFeeEstimate(dataSize int64, rewardStr string) (*FeeEstimate, error) {
	rewardStr = strings.TrimSpace(rewardStr)
	if rewardStr == "" {
		return nil, fmt.Errorf("empty reward response")
	}

	winston, err := strconv.ParseInt(rewardStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid reward value %q: %w", rewardStr, err)
	}

	rewardAR := float64(winston) / float64(WinstonPerAR)

	var dataPerAR float64
	if rewardAR > 0 {
		dataPerAR = float64(dataSize) / rewardAR
	}

	return &FeeEstimate{
		DataSize:  dataSize,
		Reward:    rewardStr,
		RewardAR:  rewardAR,
		DataPerAR: dataPerAR,
	}, nil
}
