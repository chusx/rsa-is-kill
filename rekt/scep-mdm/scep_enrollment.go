// scep_enrollment.go
//
// SCEP (Simple Certificate Enrollment Protocol) RSA-only enrollment.
// Source: micromdm/scep — https://github.com/micromdm/scep
// Specifically: scep/scep.go, cmd/scepclient/csr.go
//
// SCEP is the protocol used by every MDM system to automatically issue
// device certificates. It is the enrollment backbone for:
//   - Apple MDM (Intune, Jamf, Mosyle, Kandji) — SCEP used for WiFi and VPN certs
//   - Cisco AnyConnect / ISE — SCEP for VPN client certs
//   - Windows NDES (Network Device Enrollment Service) — Microsoft SCEP server
//   - Network equipment — Cisco, Juniper, Aruba use SCEP for device cert enrollment
//
// RFC 8894 (SCEP, 2020) specifies RSA for all cryptographic operations:
//   - The CSR is signed with the device's RSA private key
//   - The SCEP request is encrypted with the CA's RSA public key (PKCS#7)
//   - The CA response is encrypted with the client's RSA public key
//
// There is no PQC algorithm defined in RFC 8894 or any SCEP draft.
// SCEP has no algorithm negotiation — the CA and client must use RSA.

package scep

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"

	"go.mozilla.org/pkcs7"
)

// Default RSA key size for SCEP enrollment.
// Apple MDM profile specification requires RSA-2048 minimum.
// Cisco ISE SCEP requires RSA-2048.
// NDES defaults to RSA-2048.
const DefaultKeySize = 2048

// CSROption configures the certificate signing request.
type CSROption func(*x509.CertificateRequest)

// GenerateKeyAndCSR generates an RSA keypair and a PKCS#10 CSR for SCEP enrollment.
// Called by MDM clients (Apple MDM agent, Cisco AnyConnect) during device enrollment.
//
// Source: micromdm/scep cmd/scepclient/csr.go newCSR()
func GenerateKeyAndCSR(cn string, opts ...CSROption) (*rsa.PrivateKey, *x509.CertificateRequest, error) {
	// RSA-2048 private key — this is the device identity key
	// stored in the device keychain / TPM after enrollment
	key, err := rsa.GenerateKey(rand.Reader, DefaultKeySize)
	if err != nil {
		return nil, nil, err
	}

	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: cn,
		},
	}
	for _, o := range opts {
		o(tmpl)
	}

	// PKCS#10 CSR signed with the RSA private key
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, nil, err
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, err
	}

	return key, csr, nil
}

// PKIMessage is a SCEP PKIMessage (PKCS#7 wrapped request/response).
// Source: micromdm/scep scep/scep.go PKIMessage
type PKIMessage struct {
	TransactionID string
	MessageType   MessageType
	SenderNonce   []byte

	// p7 is the outer PKCS#7 SignedData envelope.
	// The signerInfo uses the client's RSA key to sign the PKIMessage.
	p7 *pkcs7.PKCS7

	// The inner envelope is PKCS#7 EnvelopedData, encrypted to the CA's
	// RSA public key. This wraps the actual CSR (for PKCSReq) or
	// issued certificate (for CertRep).
	p7Envelope *pkcs7.PKCS7
}

// PKCSReq creates an enrollment request message.
// The CSR is:
//   1. Wrapped in PKCS#7 EnvelopedData, encrypted to CA's RSA public key
//   2. Signed with the client's RSA private key (PKCS#7 SignedData)
//
// Source: micromdm/scep scep/scep.go NewCSRRequest()
func PKCSReq(csr *x509.CertificateRequest,
	clientKey *rsa.PrivateKey,   // device RSA-2048 private key
	clientCert *x509.Certificate,
	caCert *x509.Certificate,    // CA's RSA-2048 certificate (used to encrypt)
) (*PKIMessage, error) {

	// Step 1: Encrypt the CSR to the CA's RSA public key (PKCS#7 EnvelopedData)
	// Uses RSA-OAEP or RSA-PKCS1v1.5 depending on CA capabilities
	encryptedCSR, err := pkcs7.Encrypt(csr.Raw, []*x509.Certificate{caCert})
	if err != nil {
		return nil, err
	}

	// Step 2: Sign the EnvelopedData with the client's RSA private key
	sd, err := pkcs7.NewSignedData(encryptedCSR)
	if err != nil {
		return nil, err
	}

	// pkcs7.AddSigner internally calls rsa.SignPKCS1v15 with the client key
	if err := sd.AddSigner(clientCert, clientKey, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, err
	}

	p7, err := sd.Finish()
	if err != nil {
		return nil, err
	}

	return &PKIMessage{
		MessageType: PKCSReq,
		p7:          p7,
	}, nil
}

// MessageType values from RFC 8894
type MessageType string
const (
	PKCSReqMsg       MessageType = "19" // certificate enrollment
	CertRepMsg       MessageType = "3"  // CA response with issued certificate
	GetCertInitial   MessageType = "20" // poll for pending cert
)

// SCEPHandler is the server-side SCEP CA handler.
// Source: micromdm/scep server/service.go
type SCEPHandler struct {
	// CA private key — RSA-2048 (or RSA-4096 for larger deployments)
	// Used to:
	//   1. Sign issued certificates
	//   2. Decrypt incoming PKCS#7 EnvelopedData (client's encrypted CSR)
	CAKey  *rsa.PrivateKey
	CACert *x509.Certificate
}

// HandlePKCSReq processes an enrollment request.
// Decrypts the client's CSR (using CA RSA key), validates it,
// issues a certificate, returns CertRep.
func (h *SCEPHandler) HandlePKCSReq(msg *PKIMessage) (*PKIMessage, error) {
	// Decrypt the inner EnvelopedData using the CA's RSA private key.
	// If a CRQC factors the CA RSA public key, an attacker can:
	//   - Decrypt all enrollment requests (CSRs) in transit
	//   - Forge enrollment approvals for arbitrary devices
	//   - Issue certificates for any CN without going through the CA
	csrBytes, err := msg.p7Envelope.Decrypt(h.CACert, h.CAKey)
	if err != nil {
		return nil, err
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, err
	}

	// Issue certificate (sign with CA key)
	// ... serial number, validity, extensions ...
	issuedCert := h.signCSR(csr)

	return buildCertRep(issuedCert, msg.SenderNonce)
}
