# How Firefox actually uses the NSS RSA primitives

NSS (Network Security Services) is the TLS + PKI library developed by
Mozilla and reused by Red Hat Certificate System, Red Hat Directory
Server, Pidgin, Thunderbird, LibreOffice, Evolution, and the 389
Directory Server.  This note walks the real Firefox code path from a
user typing a URL to the RSA verify in `nss_rsa_freebl.c`.

## 1. URL typed → `nsDocShell::LoadURI`

Firefox resolves the URL, selects HTTP transport if the scheme is
`https:`, and kicks off a new channel via `nsHttpChannel`.

## 2. Necko → `nsHttpConnectionMgr` → `nsSocketTransport`

Creates the TCP/QUIC socket and wires up PSM (Platform Security
Module, `security/manager/ssl/`) as the TLS layer.  PSM is a thin
XPCOM wrapper around NSS.

## 3. `nsNSSIOLayer` + `SSL_ImportFD`

Hands the raw socket to NSS. ClientHello goes out, ServerHello +
certificate chain comes back. TLS 1.3 with
`TLS_AES_128_GCM_SHA256` is the baseline; RSA-PSS and RSA-PKCS1
signature algorithms remain negotiable, though the handshake uses
X25519 or P-256 for key agreement.

## 4. Chain verification — `PSM_CertVerifier::VerifySSLServerCert`

- Builds candidate paths from the server's cert chain through
  intermediates to roots in the **Mozilla CA Certificate Store**
  (`certdata.txt` → `libnssckbi.so`).  This is the root store that
  Firefox, Thunderbird, `curl` with NSS, and every RHEL / Fedora /
  CentOS TLS client ships.
- Each signature along the path is verified by NSS's **mozilla::pkix**
  library, which calls into `nss_rsa_freebl.c` for RSA-PKCS#1 v1.5
  and RSA-PSS verify. SHA-256 / SHA-384 digest, modulus 2048–4096.
- OCSP or CRLite consulted; EV / CT policy applied.

## 5. RSA verify — `RSA_CheckSign` / `RSA_CheckSignRecover`

This is where `nss_rsa_freebl.c` is finally invoked. FreeBL chooses
between the software path and any loaded PKCS#11 hardware token
(Opal-encrypted-disk tokens, soft tokens from `certutil -d`, FIPS
mode "NSS Internal FIPS PKCS #11 Module").

## 6. Client certificate auth path

When the server sends `CertificateRequest`, PSM pops the certificate
picker UI. The user's client cert private key can live in:

- `cert9.db` / `key4.db` — NSS's legacy soft-token.
- PKCS#11 hardware tokens: PIV / CAC cards via opensc-pkcs11,
  YubiKey, smart cards behind Windows CAPI through the Mozilla
  CAPI bridge module.

Signing proceeds via `RSA_Sign` in `nss_rsa_freebl.c` (or the
PKCS#11 token's own C_Sign, depending on slot).

## 7. S/MIME in Thunderbird

Thunderbird shares NSS and the certdb with Firefox profiles. S/MIME
compose → `smimeEnvelopedOutput` builds CMS SignedData+EnvelopedData
and calls RSA sign + RSA-OAEP encrypt in `nss_rsa_freebl.c`.

## Breakage under an RSA factoring attack

- **TLS server cert forgery**: any Root CA in the Mozilla store that
  signs with RSA (still the overwhelming majority) becomes
  impersonable. Attackers mint certs for arbitrary hostnames that
  every Firefox / RHEL / curl / apt / yum / dnf / OpenLDAP client
  validates.
- **OCSP response forgery**: OCSP responders sign with RSA; a
  factoring break lets attackers produce "good" responses for
  revoked certs indefinitely.
- **S/MIME mass-decrypt**: historic S/MIME encrypted mails sitting
  in corporate archives become decryptable offline if the
  recipient's RSA cert is factored.
- **Client-cert impersonation**: enterprise PIV / CAC smart-card
  cert pubkeys (RSA-2048) are observable on every TLS
  handshake; factoring lets attackers impersonate federal
  employees in NIPRNET and SIPRNET web portals to the exact
  extent RSA is still used in those hierarchies.

## Migration

Mozilla has been expanding ECDSA-P256 root representation in the
store since ~2015. `tls13-signature-algorithms-cert` lets Firefox
prefer ECDSA, but the server has to present such a cert.  The long
tail of enterprise internal CAs on RSA-2048 is where the residual
exposure lives, as of 2026.

## Source-file references inside NSS

- `security/nss/lib/freebl/rsa.c` — the RSA primitive.
- `security/nss/lib/softoken/sftkhmac.c` — RSA via PKCS#11 soft token.
- `security/nss/lib/mozpkix/lib/pkixder.cpp` — chain parsing.
- `security/manager/ssl/PublicSSLState.cpp` — PSM glue.
