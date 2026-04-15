// dhc_settlement_client.go
//
// Conexxus DHC-IP client: forecourt controller (Gilbarco Passport,
// Wayne Fusion, DFS Edge) talks to a fuel-brand back-office hub
// (Exxon EM Direct, Shell Hercules, Chevron TechConnect, BP Rolls)
// to authorize and settle fuel purchases dispensed at the pump.
//
// Every authorization ride is an ISO-8583-like message inside a
// Conexxus DHC envelope, transported over mutual-TLS with RSA-2048
// client cert issued by the brand's enterprise PKI.
//
// For an EMV-at-the-pump transaction, the dispenser's EPP also
// encrypts the PIN block under DUKPT keys previously injected by
// TR-34 RKI (see ../atm-xfs-firmware/tr34_rkl_session.c for the
// analogous bank-ATM flow).

package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

type DHCClient struct {
	hubAddr     string
	siteID      string            // site identifier assigned by brand
	conn        *tls.Conn
	cardNetworkRoots *x509.CertPool // Visa/MC + brand's own DHC CA

	// Populated at connect time from the server cert chain:
	hubSigningPub *rsa.PublicKey
}

// Connect — single persistent TLS tunnel, re-established on DPD drop.
func (c *DHCClient) Connect(ctx context.Context) error {
	// Site cert: RSA-2048 issued by brand DHC CA during commission.
	siteCert, err := tls.LoadX509KeyPair(
		"/opt/forecourt/certs/site.crt",
		"/opt/forecourt/certs/site.key", // backed by HSM engine, not disk in prod
	)
	if err != nil {
		return fmt.Errorf("load site cert: %w", err)
	}
	cfg := &tls.Config{
		Certificates:          []tls.Certificate{siteCert},
		RootCAs:               c.cardNetworkRoots,
		MinVersion:            tls.VersionTLS12,
		VerifyPeerCertificate: c.pinBrandRoot,
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := tls.DialWithDialer(dialer, "tcp", c.hubAddr, cfg)
	if err != nil {
		return fmt.Errorf("tls dial: %w", err)
	}
	c.conn = rawConn

	// Extract the hub signing pub for future DHC envelope signatures.
	cs := rawConn.ConnectionState()
	hubLeaf := cs.PeerCertificates[0]
	pub, ok := hubLeaf.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("hub cert not RSA")
	}
	c.hubSigningPub = pub
	return nil
}

// pinBrandRoot enforces that the hub leaf chains up to the brand's
// own DHC CA — not just any CA in the system trust store. Prevents
// a Let's-Encrypt-style forged-cert MITM on the hub hostname.
func (c *DHCClient) pinBrandRoot(rawCerts [][]byte,
	verifiedChains [][]*x509.Certificate) error {
	for _, chain := range verifiedChains {
		root := chain[len(chain)-1]
		if root.Subject.CommonName == "ExxonMobil DHC Root CA 2024" ||
			root.Subject.CommonName == "Shell DHC Root CA G3" ||
			root.Subject.CommonName == "Chevron TechConnect Root 2023" {
			return nil
		}
	}
	return errors.New("hub cert does not chain to pinned brand root")
}

// AuthorizeFuel submits a pre-pay authorization for a customer
// inserting a card at dispenser `pumpID`. Response carries a
// DHC-signed grant; forecourt unlocks the pump handle only when
// signature + approval code + amount-hold succeed.
func (c *DHCClient) AuthorizeFuel(pumpID int, pan, expiry string,
	preAuthCents uint32, pinBlockDUKPT, ksn []byte,
	emvARQC []byte) (*AuthResp, error) {

	req := DHCAuthRequest{
		MsgType:      0x0200,
		SiteID:       c.siteID,
		DispenserID:  uint16(pumpID),
		PAN:          pan,
		Expiry:       expiry,
		AmountCents:  preAuthCents,
		PINBlock:     pinBlockDUKPT,
		KSN:          ksn,
		EMV_ARQC:     emvARQC,
		TxnType:      TXN_FUEL_PREAUTH,
		TxnTimestamp: time.Now().Unix(),
	}
	if err := c.sendDHC(&req); err != nil {
		return nil, err
	}
	return c.recvAuthResp()
}

// SettleCompletion sends the actual dispensed gallons + dollars
// after the pump handles down. Must match or be below the preauth
// hold; brand host returns a signed settlement confirmation.
func (c *DHCClient) SettleCompletion(pumpID int,
	actualCents uint32, gallons float32, emvTC []byte) error {
	req := DHCSettleRequest{
		MsgType:     0x0220,
		SiteID:      c.siteID,
		DispenserID: uint16(pumpID),
		FinalAmount: actualCents,
		Gallons:     gallons,
		EMV_TC:      emvTC,
	}
	if err := c.sendDHC(&req); err != nil {
		return err
	}
	resp, err := c.recvSettleResp()
	if err != nil {
		return err
	}
	// Verify hub-signed settlement-confirmation. The signature is
	// what makes the back-office accounting evidence-grade.
	if err := verifyRSASig(c.hubSigningPub, resp.RawSigned, resp.Sig); err != nil {
		return fmt.Errorf("hub settlement signature bad: %w", err)
	}
	storeSignedSettlementLog(resp) // compliance: 7-year retention
	return nil
}

// ------------ Wire-format helpers ------------

type DHCAuthRequest struct {
	MsgType       uint16
	SiteID        string
	DispenserID   uint16
	PAN           string
	Expiry        string
	AmountCents   uint32
	PINBlock      []byte
	KSN           []byte
	EMV_ARQC      []byte
	TxnType       uint8
	TxnTimestamp  int64
}

type DHCSettleRequest struct {
	MsgType     uint16
	SiteID      string
	DispenserID uint16
	FinalAmount uint32
	Gallons     float32
	EMV_TC      []byte
}

type AuthResp struct {
	ApprovalCode string
	HoldCents    uint32
	Sig          []byte
}

type SettleResp struct {
	ConfirmCode string
	FinalCents  uint32
	RawSigned   []byte
	Sig         []byte
}

func (c *DHCClient) sendDHC(msg interface{}) error {
	body, _ := marshalDHC(msg)
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(body)))
	_, err := c.conn.Write(append(hdr, body...))
	return err
}

func (c *DHCClient) recvAuthResp() (*AuthResp, error) {
	var hdr [4]byte
	if _, err := c.conn.Read(hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	buf := make([]byte, n)
	if _, err := c.conn.Read(buf); err != nil {
		return nil, err
	}
	return unmarshalAuth(buf)
}

func (c *DHCClient) recvSettleResp() (*SettleResp, error) { /* ... */ return nil, nil }
func marshalDHC(msg interface{}) ([]byte, error)         { /* ... */ return nil, nil }
func unmarshalAuth(b []byte) (*AuthResp, error)          { /* ... */ return nil, nil }
func verifyRSASig(pub *rsa.PublicKey, data, sig []byte) error { /* ... */ return nil }
func storeSignedSettlementLog(r *SettleResp)             { /* ... */ }

const TXN_FUEL_PREAUTH = 0x10

func main() {
	roots := x509.NewCertPool()
	pem, _ := os.ReadFile("/etc/brand-dhc-roots.pem")
	roots.AppendCertsFromPEM(pem)
	c := &DHCClient{
		hubAddr:          "hercules.shell.com:443",
		siteID:           "US-SHELL-SITE-104387",
		cardNetworkRoots: roots,
	}
	_ = c.Connect(context.Background())
}

// ---- Breakage ----
//
// Factor the brand DHC CA (Shell / ExxonMobil / Chevron / BP /
// TotalEnergies):
//   - Attacker stands up a rogue DHC hub, mints a hub cert that
//     passes pinBrandRoot(), and MITM's site-to-hub authorization
//     traffic. Approves/declines fraudulent transactions. Forges
//     settlement records into the brand's nightly reconciliation.
//     One compromised brand CA touches ~10-20% of US retail fuel.
//
// Factor a site (forecourt) cert:
//   - Attacker connects to the hub as a legitimate site, submits
//     forged authorizations for actual card numbers captured via
//     skimmers elsewhere. Harder-to-trace funds laundering through
//     fake fuel purchases.
//
// Factor a dispenser-vendor firmware-signing CA (see README):
//   - Fleet-wide PIN and magstripe/EMV harvesting through "vendor-
//     signed" firmware at hundreds of thousands of pumps.
//
// Factor an EPA / ATG signing root:
//   - Underground storage-tank leak logs become forgeable;
//     environmental enforcement evidence chain for 150k+ US
//     retail stations is compromised.
