// Source: hashicorp/vault builtin/logical/pki/
//
// HashiCorp Vault is the dominant secrets management platform in cloud-native
// infrastructure. The Vault PKI secrets engine issues X.509 certificates and
// acts as an internal CA for:
//   - Service mesh mTLS (Consul Connect, Istio + Vault CA, Linkerd)
//   - Kubernetes dynamic certificate issuance (cert-manager + Vault)
//   - Database credential certificates
//   - SSH certificate authorities
//   - Internal enterprise CAs (replacing Windows ADCS in many shops)
//
// Vault PKI default key type: RSA-2048.
// Operators routinely deploy root CAs with 10-year validity and RSA-2048 keys.
// Every certificate issued under that root inherits the RSA trust chain.
// No PQC algorithm is supported in Vault PKI (as of Vault 1.17).

package pki

import (
    "crypto/rsa"
    "crypto/x509"
    "crypto/rand"
    "math/big"
    "time"
)

// Default certificate parameters in Vault PKI (from vault/builtin/logical/pki/):
const (
    DefaultKeyType   = "rsa"       // RSA is the default key type
    DefaultKeyBits   = 2048        // RSA-2048 default
    DefaultSignatureBits = 256     // SHA-256 with RSA → SHA256withRSAEncryption
    MaxRootCAValidity = 10         // 10-year root CA validity (common in practice)
)

// GeneratePrivateKey generates the private key for a Vault PKI role.
// Default invocation: keyType="rsa", keyBits=2048.
// No PQC key type is accepted; attempting "ml-dsa" returns an error.
func GeneratePrivateKey(keyType string, keyBits int) (interface{}, error) {
    switch keyType {
    case "rsa":
        // RSA key generation — broken by Shor's algorithm
        // keyBits=2048 by default; some ops teams use 4096
        return rsa.GenerateKey(rand.Reader, keyBits)

    case "ec":
        // ECDSA key generation — also broken by Shor's algorithm
        curve := selectCurve(keyBits)  // P-256, P-384, or P-521
        return ecdsa.GenerateKey(curve, rand.Reader)

    case "ed25519":
        // EdDSA — also broken by Shor's algorithm
        _, priv, err := ed25519.GenerateKey(rand.Reader)
        return priv, err

    // "ml-dsa", "ml-kem", "slh-dsa" — not handled, returns error
    default:
        return nil, fmt.Errorf("unknown key type: %q", keyType)
    }
}

// GenerateCertificate creates an X.509 certificate signed with RSA-2048.
// Called for every certificate issued by a Vault PKI role.
// The x509.Certificate.SignatureAlgorithm will be x509.SHA256WithRSA.
//
// Vault PKI root CA issuance pattern in production:
//   vault write pki/root/generate/internal \
//       key_type=rsa key_bits=2048 \          ← RSA-2048 default
//       ttl=87600h                            ← 10-year validity
//       common_name="internal-ca"
//
// All intermediate CAs and leaf certs issued under this root are signed
// with SHA256withRSAEncryption. A CRQC compromising the root RSA-2048 key
// allows forging certificates for any service in the Vault PKI hierarchy.
func GenerateCertificate(template *x509.Certificate,
                          parent *x509.Certificate,
                          pub interface{},
                          priv interface{}) (*x509.Certificate, error) {

    // If priv is *rsa.PrivateKey (default), this produces SHA256withRSAEncryption
    // If priv is *ecdsa.PrivateKey, produces ECDSAWithSHA256/384/512
    // No PQC algorithm path exists in crypto/x509
    certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
    if err != nil {
        return nil, err
    }
    return x509.ParseCertificate(certDER)
}

// Service mesh impact:
// Consul Connect with Vault CA:
//   - Every service sidecar proxy gets a leaf cert every 72 hours
//   - Root CA: RSA-2048, 10yr validity
//   - Intermediate CA: RSA-2048, 1yr validity
//   - Leaf: RSA-2048, 72hr validity
//
// Istio with Vault CA (istio-csr + cert-manager):
//   - Same hierarchy; istiod rotates workload certs every 24 hours
//   - The root RSA-2048 key is the single point of failure
//
// cert-manager + Vault PKI (Kubernetes):
//   - Issues TLS certs for every Ingress and Service in the cluster
//   - Default issuer profile: RSA-2048
//
// All of these inherit the same PQC gap: no PQC issuer profile in cert-manager,
// no PQC support in Vault PKI, no PQC in Go's crypto/x509 (as of Go 1.22).
