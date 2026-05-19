// Package ipfar provides high-level IPFAR upload/download/dedup/verify APIs.
package ipfar

// UploadResult holds the result of a file upload through the IPFAR pipeline.
type UploadResult struct {
	RootCID    string // Root CID of the uploaded file
	DataTXID   string // Arweave transaction ID of the CAR data
	MetaTXID   string // Arweave transaction ID of the metadata
	DataHeight int    // Block height of the CAR transaction
	DataSize   int64  // Original file size in bytes
}

// VerifyResult holds the result of an on-chain verification.
type VerifyResult struct {
	Valid        bool     // Overall validity
	CARVerified  bool     // CAR data integrity verified
	MetaVerified bool     // Metadata integrity verified
	PoWVerified  bool     // PoW verified (if applicable)
	Errors       []string // Detailed error messages
}

// AddError appends an error message to the result and marks it invalid.
func (r *VerifyResult) AddError(msg string) {
	r.Errors = append(r.Errors, msg)
	r.Valid = false
}
