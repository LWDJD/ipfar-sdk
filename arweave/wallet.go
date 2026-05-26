// Package arweave provides an Arweave gateway client with wallet management,
// transaction building/signing, and chunked upload support.
package arweave

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
)

// JWK represents an Arweave JWK (JSON Web Key) RSA key file.
type JWK struct {
	N string `json:"n"`
	E string `json:"e"`
	D string `json:"d"`
	P string `json:"p"`
	Q string `json:"q"`
}

// Wallet holds the parsed RSA private key and derived Arweave identifiers.
type Wallet struct {
	PrivateKey *rsa.PrivateKey
	Owner      string // Base64URL-encoded modulus N
	Address    string // Base64URL-encoded SHA-256 of modulus N
}

// LoadWalletFromFile reads a JWK JSON file and returns a Wallet.
func LoadWalletFromFile(path string) (*Wallet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read wallet file: %w", err)
	}
	return LoadWalletFromJSON(data)
}

// LoadWalletFromJSON parses JWK JSON bytes and returns a Wallet.
func LoadWalletFromJSON(data []byte) (*Wallet, error) {
	var jwk JWK
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, fmt.Errorf("failed to parse JWK: %w", err)
	}
	return newWalletFromJWK(&jwk)
}

// newWalletFromJWK constructs a Wallet from decoded JWK fields.
func newWalletFromJWK(jwk *JWK) (*Wallet, error) {
	n, err := decodeBase64BigInt(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("invalid modulus (n): %w", err)
	}
	e, err := decodeBase64BigInt(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("invalid exponent (e): %w", err)
	}
	d, err := decodeBase64BigInt(jwk.D)
	if err != nil {
		return nil, fmt.Errorf("invalid private exponent (d): %w", err)
	}

	nBytes := n.Bytes()
	privKey := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: n,
			E: int(e.Int64()),
		},
		D: d,
	}

	// Parse optional CRT primes for performance.
	if jwk.P != "" {
		p, err := decodeBase64BigInt(jwk.P)
		if err == nil {
			privKey.Primes = append(privKey.Primes, p)
		}
	}
	if jwk.Q != "" {
		q, err := decodeBase64BigInt(jwk.Q)
		if err == nil {
			privKey.Primes = append(privKey.Primes, q)
		}
	}

	privKey.Precompute()

	owner := base64.RawURLEncoding.EncodeToString(nBytes)
	h := sha256.Sum256(nBytes)
	address := base64.RawURLEncoding.EncodeToString(h[:])

	return &Wallet{
		PrivateKey: privKey,
		Owner:      owner,
		Address:    address,
	}, nil
}

// decodeBase64BigInt decodes a base64url-encoded string into a big.Int.
func decodeBase64BigInt(s string) (*big.Int, error) {
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(data), nil
}
