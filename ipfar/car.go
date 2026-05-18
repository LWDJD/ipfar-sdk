package ipfar

import (
	"context"
	"fmt"

	"github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"

	"github.com/LWDJD/ipfar-sdk/car"
)

// BuildCarV2 creates a CAR v2 file with a single raw block containing data.
// Delegates to the standard CAR v2 builder in the car package.
// Returns the CAR bytes, the root CID, and an error if any.
func BuildCarV2(data []byte) (carBytes []byte, rootCID cid.Cid, err error) {
	// Compute CID first
	mhHash, err := mh.Sum(data, mh.SHA2_256, -1)
	if err != nil {
		return nil, cid.Undef, fmt.Errorf("failed to hash data: %w", err)
	}
	rootCID = cid.NewCidV1(cid.Raw, mhHash)

	// Delegate to the standard CAR v2 builder
	carBytes, err = car.BuildCAR(context.Background(), data, rootCID.String())
	if err != nil {
		return nil, cid.Undef, fmt.Errorf("BuildCAR failed: %w", err)
	}

	return carBytes, rootCID, nil
}

// ComputeCID computes the CID v1 (raw + sha2-256) for the given data.
func ComputeCID(data []byte) (cid.Cid, error) {
	hash, err := mh.Sum(data, mh.SHA2_256, -1)
	if err != nil {
		return cid.Undef, fmt.Errorf("failed to hash data: %w", err)
	}
	return cid.NewCidV1(cid.Raw, hash), nil
}
