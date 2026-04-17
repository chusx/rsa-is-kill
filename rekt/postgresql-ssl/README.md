# postgresql-ssl — RSA client certificate authentication to databases

**Repository:** git.postgresql.org 
**Industry:** Financial, healthcare, government — any hardened database deployment 
**Algorithm:** RSA-2048 server and client certificates 

## What it does

PostgreSQL supports client certificate authentication (the `cert` auth method in
`pg_hba.conf`). When configured with `hostssl ... cert`, connecting clients must
present a valid RSA-2048 X.509 certificate. The certificate Common Name (CN) maps
to the PostgreSQL username. No password is used — the certificate IS the credential.

Used in:
- **Payment processors** — database servers behind PCI-DSS require strong authentication; RSA client certs are the compliance-friendly option
- **Healthcare** — HIPAA-regulated PostgreSQL databases require authentication without passwords in config files; cert auth delivers this
- **FedRAMP/FISMA** — US government cloud databases require certificate-based authentication per NIST SP 800-53 IA-2
- **Kubernetes** — cert-manager issues RSA-2048 certificates for pod-to-database mTLS; PostgreSQL validates them with cert auth
- **Multi-tenant SaaS** — per-tenant certificates for logical database access separation

The server's RSA-2048 certificate authenticates PostgreSQL to the client.
The client's RSA-2048 certificate authenticates the application to PostgreSQL.
Both sides use the enterprise CA (ADCS, Vault PKI, or cert-manager) for issuance.

## Why it's stuck

- PostgreSQL uses OpenSSL for TLS. OpenSSL's ML-KEM support (TLSEXT_TYPE_kem_groups)
 is in 3.2+ but the cipher suite infrastructure for ML-DSA is not yet production-ready
- No non-RSA certificate type exists in PostgreSQL's `ssl_cert_file` or client cert
 handling code. `pg_hba.conf` cert auth extracts the X.509 CN — non-RSA cert format
 is not yet standardized
- Amazon RDS, Azure Database for PostgreSQL, and Google Cloud SQL all use OpenSSL-backed
 RSA certificates for their "require SSL" configurations. Cloud provider timelines
 for non-RSA database TLS have not been announced
- Database certificate issuance in enterprises goes through ADCS or Vault PKI
 (see those samples) — neither supports non-RSA yet

## impact

the database is where the actual data lives. RSA client certs are the auth mechanism.
forge the cert, access the database.

- forge a client certificate with CN=postgres (the superuser), present it to any
 PostgreSQL server using cert auth. pg_hba.conf matches on the CN, grants superuser
 access. dump the entire database
- payment processor databases using PCI-DSS cert auth: forge the application's
 RSA client cert and you're connecting as the payment application. SELECT on
 the transactions table, card data, PAN numbers — whatever the app account can access
- healthcare PostgreSQL: forge the EHR application's cert, access patient records.
 the cert auth was supposed to prevent password-in-config exposure; it trades
 that risk for RSA-key-on-blockchain-equivalent exposure
- Kubernetes service certs: cert-manager issues RSA-2048 certs to every pod that
 connects to the database. forge any pod's cert, connect to the database as that
 service account. the Kubernetes network policy trusts any pod with a valid cert

## Code

`pg_rsa_client_auth.c` — `be_tls_open_server()` (RSA cert loading, SSL_VERIFY_PEER
for client cert auth, CN extraction for username mapping), `pgtls_get_peer_certificate_hash()`
(SHA-256 of server RSA cert for TLS channel binding), and `pg_hba.conf` examples
showing the cert auth configuration. From `src/backend/libpq/be-secure-openssl.c`
and `src/interfaces/libpq/fe-secure-openssl.c` on `git.postgresql.org`.
