// notary_rsa_root.go
//
// Docker Notary / TUF (The Update Framework) — RSA root keys for container signing.
// Repository: theupdateframework/notary (https://github.com/theupatefreamework/notary)
//             theupdateframework/go-tuf (https://github.com/theupdateframework/go-tuf)
//
// Docker Content Trust (DCT) uses Notary, which implements TUF, to sign container images.
// The TUF root key is the trust anchor for the entire signing hierarchy.
//
// TUF role hierarchy:
//   root key    — signs root metadata; RSA-4096 (Notary default)
//     |
//   targets key — signs image manifests; RSA-2048
//     |
//   snapshot key— signs metadata snapshot; RSA-2048
//     |
//   timestamp key — signs freshness metadata; RSA-2048 (held by Notary server)
//
// The root key is RSA-4096 by default in Notary. It's stored offline (should be).
// The targets key is RSA-2048, stored in the Docker trust store.
//
// Used by:
//   - Docker Hub official images (library/*, all official images)
//   - AWS ECR (uses Notary for container signing in ECR Image Signing)
//   - Quay.io / Red Hat
//   - Docker Enterprise (Kubernetes deployments with DCT enabled)
//
// ~/.docker/trust/private/ contains the targets and snapshot RSA-2048 private keys.
// The keys are stored passphrase-encrypted but the PUBLIC keys are in the Notary server.

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"
)

// TUF metadata types
const (
	TUFRootRole      = "root"
	TUFTargetsRole   = "targets"
	TUFSnapshotRole  = "snapshot"
	TUFTimestampRole = "timestamp"

	// RSA key sizes per Notary defaults
	RootKeyBits    = 4096 // root key: RSA-4096
	TargetsKeyBits = 2048 // targets key: RSA-2048
)

// TUFKey represents a public key in TUF metadata
type TUFKey struct {
	KeyType string `json:"keytype"` // "rsa"
	KeyVal  struct {
		Public string `json:"public"` // PEM-encoded RSA public key
	} `json:"keyval"`
}

// TUFRootMetadata is the root.json metadata file signed by the root key
type TUFRootMetadata struct {
	Signed struct {
		Type        string             `json:"_type"`  // "Root"
		SpecVersion string             `json:"spec_version"`
		Version     int                `json:"version"`
		Expires     time.Time          `json:"expires"`
		Keys        map[string]TUFKey  `json:"keys"` // key ID -> TUFKey
		Roles       map[string]struct {
			KeyIDs    []string `json:"keyids"`
			Threshold int      `json:"threshold"`
		} `json:"roles"`
	} `json:"signed"`
	Signatures []struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"` // base64(RSA-4096 PKCS#1 v1.5 signature)
	} `json:"signatures"`
}

// GenerateRSARootKey generates the TUF root key (RSA-4096 per Notary default).
// This is the trust anchor for the entire container signing hierarchy.
// The private key is stored offline; the public key is in root.json on the Notary server.
// The root.json is downloadable by anyone who can reach the Notary server.
func GenerateRSARootKey() (*rsa.PrivateKey, error) {
	// RSA-4096 — Notary default for root keys
	// The modulus is 512 bytes; this is what Shor's algorithm factors
	key, err := rsa.GenerateKey(rand.Reader, RootKeyBits)
	if err != nil {
		return nil, fmt.Errorf("generating root key: %w", err)
	}
	return key, nil
}

// SignTUFMetadata signs TUF metadata with an RSA key (PKCS#1 v1.5 / SHA-256).
// Called when publishing new root.json, targets.json, or snapshot.json.
// The Notary server signs timestamp.json with its own RSA-2048 key.
func SignTUFMetadata(metadata []byte, signingKey *rsa.PrivateKey) ([]byte, string, error) {
	// Compute SHA-256 of the canonical JSON metadata
	digest := sha256.Sum256(metadata)

	// RSA PKCS#1 v1.5 signature (Notary uses RSASSA-PKCS1-v1_5 with SHA-256)
	signature, err := rsa.SignPKCS1v15(rand.Reader, signingKey, crypto.SHA256, digest[:])
	if err != nil {
		return nil, "", fmt.Errorf("signing metadata: %w", err)
	}

	// Compute key ID: SHA-256 of the DER-encoded public key
	pubDER, err := x509.MarshalPKIXPublicKey(&signingKey.PublicKey)
	if err != nil {
		return nil, "", err
	}
	keyIDBytes := sha256.Sum256(pubDER)
	keyID := fmt.Sprintf("%x", keyIDBytes)

	return signature, keyID, nil
}

// VerifyTUFSignature verifies an RSA signature on TUF metadata.
// Called by Docker clients when verifying image manifests.
// The public key comes from root.json on the Notary server.
func VerifyTUFSignature(metadata, signature []byte, pubKey *rsa.PublicKey) error {
	digest := sha256.Sum256(metadata)
	// RSA PKCS#1 v1.5 verify — RSA-4096 for root, RSA-2048 for targets
	return rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest[:], signature)
}

// BuildRootMetadata builds a TUF root.json with RSA keys.
// root.json is stored on the Notary server and is downloadable by any Docker client.
// It contains the RSA-4096 root public key and RSA-2048 targets/snapshot public keys.
// The root.json is the CRQC input: all public keys are in it, unencrypted.
func BuildRootMetadata(rootKey, targetsKey, snapshotKey, timestampKey *rsa.PrivateKey) ([]byte, error) {
	rootPub := publicKeyToPEM(&rootKey.PublicKey)
	targetsPub := publicKeyToPEM(&targetsKey.PublicKey)
	snapshotPub := publicKeyToPEM(&snapshotKey.PublicKey)
	timestampPub := publicKeyToPEM(&timestampKey.PublicKey)

	// In real Notary: key ID = SHA-256(DER(public key))
	// Simplified here
	root := TUFRootMetadata{}
	root.Signed.Type = "Root"
	root.Signed.SpecVersion = "1.0.0"
	root.Signed.Version = 1
	root.Signed.Expires = time.Now().Add(365 * 24 * time.Hour)
	root.Signed.Keys = map[string]TUFKey{
		"root-key-id": {
			KeyType: "rsa",
			KeyVal:  struct{ Public string `json:"public"` }{Public: rootPub},
		},
		"targets-key-id": {
			KeyType: "rsa",
			KeyVal:  struct{ Public string `json:"public"` }{Public: targetsPub},
		},
		"snapshot-key-id": {
			KeyType: "rsa",
			KeyVal:  struct{ Public string `json:"public"` }{Public: snapshotPub},
		},
		"timestamp-key-id": {
			KeyType: "rsa",
			KeyVal:  struct{ Public string `json:"public"` }{Public: timestampPub},
		},
	}
	// ... roles omitted for brevity

	_ = snapshotPub
	_ = timestampPub

	return json.Marshal(root)
}

func publicKeyToPEM(pub *rsa.PublicKey) string {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return string(pem.EncodeToMemory(block))
}

// GetDockerTrustStoreKeys returns paths to RSA keys in Docker's trust store.
// These files exist on every Docker host using Docker Content Trust.
// They contain RSA-2048 targets keys for each signed repository.
func GetDockerTrustStoreKeys() []string {
	// Docker trust store: ~/.docker/trust/private/
	// Files are passphrase-encrypted PEM RSA keys
	// The passphrase is often empty or a weak user password
	return []string{
		"~/.docker/trust/private/root_keys/*.key",   // RSA-4096 root (should be offline)
		"~/.docker/trust/private/tuf_keys/*.key",    // RSA-2048 targets/snapshot
		"~/.docker/trust/tuf/docker.io/*/metadata/", // metadata cache (public keys in JSON)
	}
}
