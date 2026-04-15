# nss-firefox — RSA in Mozilla NSS (Firefox, Thunderbird, RHEL)

**Repository:** hg.mozilla.org (Mercurial) — `security/nss/lib/freebl/rsa.c`  
**Industry:** Web browsers, email clients, Linux enterprise OS  
**Algorithm:** RSA-2048 / RSA-4096 — all TLS cert operations, document signing  
**PQC migration plan:** Partial — NSS has experimental ML-KEM (key exchange only); no ML-DSA; RSA still used for all authentication

## What it does

Mozilla NSS (Network Security Services) is the cryptographic library used by Firefox,
Thunderbird, and the entire RHEL/Fedora/CentOS ecosystem. It is not OpenSSL. Firefox
does not use OpenSSL; it uses NSS (and BoringSSL for some operations).

NSS provides the TLS stack, certificate validation, and asymmetric crypto for:
- **Firefox** — all HTTPS connections, 1.5 billion installs
- **Thunderbird** — S/MIME email signing/encryption
- **RHEL / CentOS / Fedora** — system crypto (`/etc/pki/nssdb/`); curl, wget, yum, dnf, subscription-manager all go through NSS
- **LibreOffice** — document digital signatures via NSS PKCS#11
- **Pidgin, Evolution, and other GTK/GNOME apps** — SSL via GnuTLS or NSS

The freebl library (`lib/freebl/`) is NSS's "low-level" crypto, containing the actual
RSA implementation. `RSA_PrivateKeyOp()` uses CRT (Chinese Remainder Theorem)
for fast decryption, `RSA_PrivateKeyOpDoubleChecked()` adds blinding to resist
fault attacks. Both ultimately call `mp_exptmod()` — multi-precision modular
exponentiation over the RSA modulus.

NSS added experimental ML-KEM in 2024. No ML-DSA. RSA is still used for all
TLS server certificate authentication (verifying `CertificateVerify`),
TLS client certificate authentication, and document signing.

## Why it's stuck

- Firefox's TLS authentication still relies on RSA certificate chains. ML-KEM
  protects the session key (forward secrecy) but does not replace RSA cert auth
- The NSS certificate database format (`cert9.db`, `key4.db`) has no PQC key type.
  `certutil -g` (NSS key generation tool) has no PQC option
- RHEL system crypto migration to PQC requires coordinating NSS, OpenSSL (FIPS module),
  GnuTLS, and Java's NSS bridge — Red Hat has published intentions but no GA date
- Thunderbird S/MIME is blocked by the same LAMPS WG S/MIME PQC gap as smime-email/
- The NSS PKCS#11 bridge (used by LibreOffice, Evolution) has no CKM_ML_DSA mechanism

## impact

NSS is the crypto stack for a billion Firefox users and the entire RHEL ecosystem.
every HTTPS certificate Firefox validates is RSA (or ECDSA). every RHEL system's
package manager trusts RSA-signed certificate chains.

- forge a TLS certificate for any site that chains to an RSA root CA trusted by NSS.
  Firefox shows a green padlock. no warning, no error, complete MitM on HTTPS for
  every Firefox user hitting that site
- the RHEL system NSS trust store contains root CAs. forge a cert trusted by those
  CAs and every system tool (yum, dnf, curl, subscription-manager) accepts it.
  push malicious packages, intercept subscription credentials, MitM system updates
  on every RHEL server globally
- Thunderbird S/MIME uses NSS for certificate verification. forge RSA signatures on
  S/MIME email, and Thunderbird shows a verified sender badge on phishing email
- the freebl RSA operations are what NSS calls for every TLS handshake. the
  vulnerability is in the math: `mp_exptmod(&c, &e, &n, &m)` in RSA_PublicKeyOp()
  is what a CRQC inverts when it solves the factoring problem

## Code

`nss_rsa_freebl.c` — `RSA_PrivateKeyOp()` (CRT-based RSA decryption/signing),
`RSA_PublicKeyOp()` (RSA public exponentiation for verification), and
`RSA_PrivateKeyOpDoubleChecked()` (blinded variant used in TLS). From
`security/nss/lib/freebl/rsa.c` in `hg.mozilla.org/mozilla-central`.
