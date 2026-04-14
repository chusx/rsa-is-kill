// Source: go-ethereum - https://github.com/ethereum/go-ethereum
// Files:  crypto/crypto.go  +  crypto/signature_cgo.go
// License: LGPL-2.1
//
// Relevant excerpt: Ethereum's cryptographic identity is entirely built
// on secp256k1 ECDSA.  An Ethereum address IS the last 20 bytes of the
// Keccak-256 hash of a secp256k1 public key.  There is no way to use a
// different signature scheme without changing what an "address" means -
// i.e. a hard protocol break.
//
// Vitalik Buterin has proposed account abstraction (EIP-7702 / ERC-4337)
// as the migration path, but as of 2026 it is optional and undeployed
// for the vast majority of accounts.  Every EOA (externally owned account)
// - which is every non-contract wallet - remains secp256k1 only.

package crypto

import "github.com/ethereum/go-ethereum/crypto/secp256k1"

// S256 returns an instance of the secp256k1 curve.
// This is the ONLY curve used anywhere in the Ethereum protocol.
func S256() elliptic.Curve {
	return secp256k1.S256()
}

// GenerateKey generates a new secp256k1 private key.
// No other curve is supported at the protocol level.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(S256(), rand.Reader)
}

// toECDSA creates a private key with secp256k1 hardwired as the curve.
func toECDSA(d []byte, strict bool) (*ecdsa.PrivateKey, error) {
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = S256() // <-- hardcoded, not negotiated
	if strict && 8*len(d) != priv.Params().BitSize {
		return nil, fmt.Errorf("invalid length, need %d bits", priv.Params().BitSize)
	}
	priv.D = new(big.Int).SetBytes(d)
	priv.PublicKey.X, priv.PublicKey.Y = S256().ScalarBaseMult(d)
	return priv, nil
}

// secp256k1 order constants - malleability rejection for Homestead
var (
	secp256k1N     = S256().Params().N
	secp256k1halfN = new(big.Int).Div(secp256k1N, big.NewInt(2))
)

// --- from crypto/signature_cgo.go ---

// Sign calculates an ECDSA signature.
// The produced signature is in the [R || S || V] format where V is 0 or 1.
// WARNING: the hash must NOT be chosen by an adversary (use Keccak256 of msg).
func Sign(hash []byte, prv *ecdsa.PrivateKey) (sig []byte, err error) {
	if len(hash) != 32 {
		return nil, fmt.Errorf("hash is required to be exactly 32 bytes (%d)", len(hash))
	}
	seckey := math.PaddedBigBytes(prv.D, prv.Params().BitSize/8)
	defer zeroBytes(seckey)
	// secp256k1_sign_recoverable - C library call, no algorithm agility
	return secp256k1.Sign(hash, seckey)
}

// Ecrecover returns the uncompressed public key that created the given signature.
// Used by every transaction validation in the EVM - hardcoded to secp256k1.
func Ecrecover(hash, sig []byte) ([]byte, error) {
	return secp256k1.RecoverPubkey(hash, sig)
}

// VerifySignature checks that the given public key created signature over hash.
func VerifySignature(pubkey, hash, signature []byte) bool {
	return secp256k1.VerifySignature(pubkey, hash, signature)
}
