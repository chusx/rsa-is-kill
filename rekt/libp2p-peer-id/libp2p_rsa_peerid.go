// libp2p_rsa_peerid.go
//
// libp2p RSA-2048 peer identity — used by IPFS and many Web3 projects.
// Source: libp2p/go-libp2p-core (now libp2p/go-libp2p)
// GitHub: https://github.com/libp2p/go-libp2p/blob/master/core/peer/peer.go
//         https://github.com/libp2p/go-libp2p-crypto (RSA key type)
//
// Every libp2p peer has a permanent identity derived from a cryptographic key.
// Peer IDs are content-addressed identifiers: SHA-256(marshalled public key),
// encoded as a multihash. RSA-2048 is one of the supported key types.
//
// IPFS uses libp2p for all peer-to-peer communication. Historical IPFS nodes
// (pre-2020) defaulted to RSA-2048 peer keys. Many long-running IPFS gateway
// nodes, Filecoin storage providers, and infrastructure nodes still use RSA keys.
//
// Filecoin (the storage network) uses secp256k1 for wallet keys and
// BLS-12-381 for validator keys — but peer authentication (the libp2p layer)
// uses RSA-2048 or Ed25519 depending on node configuration.

package peer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/multiformats/go-multihash"
	proto "google.golang.org/protobuf/proto"
)

// KeyType values from libp2p crypto protobuf
const (
	KeyType_RSA       = 0  // RSA-2048 (legacy default for IPFS)
	KeyType_Ed25519   = 1  // current default for new nodes
	KeyType_Secp256k1 = 2
	KeyType_ECDSA     = 3
)

// PublicKey is the libp2p public key interface.
// Source: go-libp2p/core/crypto/key.go
type PublicKey interface {
	Type() int32
	Bytes() ([]byte, error)
	Verify(data []byte, sig []byte) (bool, error)
}

// RsaPublicKey wraps an RSA public key for libp2p.
// Source: go-libp2p/core/crypto/rsa.go
type RsaPublicKey struct {
	k *rsa.PublicKey
}

// Type returns KeyType_RSA = 0.
func (pk *RsaPublicKey) Type() int32 {
	return KeyType_RSA
}

// Verify checks an RSA PKCS#1 v1.5 SHA-256 signature.
// Used during the libp2p Noise or TLS handshake to verify peer identity.
func (pk *RsaPublicKey) Verify(data []byte, sig []byte) (bool, error) {
	h := sha256.Sum256(data)
	err := rsa.VerifyPKCS1v15(pk.k, 0 /* crypto.SHA256 */, h[:], sig)
	if err != nil {
		return false, nil
	}
	return true, nil
}

// IDFromPublicKey derives a peer.ID from a public key.
// For RSA-2048 keys, the ID is a SHA-256 multihash of the protobuf-encoded key.
// For Ed25519 keys under 42 bytes, the identity multihash is used directly.
//
// Source: go-libp2p/core/peer/peer.go IDFromPublicKey()
func IDFromPublicKey(pk PublicKey) (ID, error) {
	pkBytes, err := pk.Bytes()
	if err != nil {
		return "", err
	}

	// RSA keys are too large for identity multihash; SHA-256 is used.
	// The SHA-256 of the protobuf-marshalled public key becomes the peer ID.
	// This means: know the RSA public key -> know the peer ID.
	// (Peer IDs are public, advertised in DHT, gossipsub, etc.)
	//
	// A CRQC: peer ID is public -> public key is public -> factor RSA ->
	// derive private key -> impersonate peer in all libp2p connections.
	var alg uint64 = multihash.SHA2_256
	if len(pkBytes) <= 42 {
		alg = multihash.IDENTITY
	}

	hash, err := multihash.Sum(pkBytes, alg, -1)
	if err != nil {
		return "", fmt.Errorf("error hashing key: %w", err)
	}

	return ID(hash), nil
}

// GenerateRSAKeyPair generates a libp2p RSA-2048 identity keypair.
// Source: go-libp2p/core/crypto/rsa.go GenerateRSAKeyPair()
//
// This was the default when running `ipfs init` before go-ipfs 0.9.0
// (which changed the default to Ed25519). Any node initialized before
// ~2021 with the default settings has an RSA-2048 peer identity.
func GenerateRSAKeyPair(bits int) (*RsaPrivateKey, *RsaPublicKey, error) {
	// bits = 2048 for legacy IPFS nodes
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	pk := &RsaPublicKey{k: &priv.PublicKey}
	sk := &RsaPrivateKey{k: priv}
	return sk, pk, nil
}

// RsaPrivateKey wraps an RSA private key for libp2p.
type RsaPrivateKey struct {
	k *rsa.PrivateKey
}

// Sign signs data with RSA PKCS#1 v1.5 SHA-256.
// Called during libp2p Noise handshake (XX pattern) to sign the handshake payload,
// proving possession of the private key corresponding to the claimed peer ID.
func (sk *RsaPrivateKey) Sign(data []byte) ([]byte, error) {
	h := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, sk.k, 0 /* crypto.SHA256 */, h[:])
}

/*
 * Scale / ecosystem context:
 *
 * IPFS has ~300,000 active peers at any time in the DHT.
 * Filecoin mainnet has ~4,000 storage providers.
 * Many IPFS pinning services (Pinata, Infura, Cloudflare) run long-lived
 * nodes that were initialized with RSA-2048 peer keys and haven't rotated.
 *
 * Peer IDs are permanently published in the DHT and in IPFS content paths.
 * An attacker with a CRQC can:
 *   - Factor any RSA-2048 peer public key (available in the DHT)
 *   - Impersonate that peer ID in all libp2p connections
 *   - Inject arbitrary data into IPFS content streams from that peer
 *   - For Filecoin storage providers: forge storage proofs, steal rewards,
 *     disrupt storage deals — the libp2p identity is the provider identity
 *
 * The libp2p spec has no PQC key type defined. The go-libp2p roadmap has
 * no PQC work item. Migration requires: new key type in the spec,
 * a new multihash for peer IDs, and coordinated rollout across all peers.
 */

// ID is a libp2p peer identifier (multihash of public key).
type ID string
