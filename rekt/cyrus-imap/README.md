# cyrus-imap — RSA in IMAP/POP3 server TLS (Kolab, universities, ISPs)

**Repository:** cyrusimap/cyrus-imapd (cyrusimap.org) 
**Industry:** Email infrastructure — universities, ISPs, German government (Kolab) 
**Algorithm:** RSA-2048 (IMAP/POP3/LMTP TLS server certificate) 

## What it does

Cyrus IMAP is the email server backend for IMAP, POP3, and LMTP. It serves email
to connected clients over TLS. The server certificate is RSA-2048 loaded from
the `tls_cert_file` in imapd.conf.

Notable deployments:
- **Carnegie Mellon University** (original developer, runs Cyrus for all CMU email)
- **Kolab Groups Suite** — Cyrus is the mail storage backend. Kolab is the open-source
 groupware recommended by the German BSI as an Exchange replacement
- **German Federal Government** — several ministries and the Bundeswehr use Kolab+Cyrus
 for internal email. The BSI approval makes this a government-grade email infrastructure
- **Fastmail** — used Cyrus in earlier architecture
- **Hundreds of universities** — Cyrus was the dominant academic IMAP server through the 2000s-2010s
- **Swiss Federal Administration** — uses Kolab

Cyrus uses OpenSSL for TLS in `imap/tls.c`. The `tls_init_serverengine()` function loads
the RSA-2048 certificate and key at startup. The cipher list `HIGH:!aNULL:!MD5` includes
RSA ciphers and excludes nothing on the grounds of being -vulnerable.

## Why it's stuck

- Cyrus depends on OpenSSL for all TLS operations. OpenSSL non-RSA support is experimental
 and not in any stable release used by Cyrus package builds
- `imapd.conf` has `tls_cert_file` and `tls_key_file` options that expect RSA or ECDSA PEM.
 There is no mechanism to specify a non-RSA key type
- Cyrus IMAP certificate issuance comes from the enterprise CA (ADCS, Let's Encrypt, etc.),
 none of which issue non-RSA certs for IMAP servers
- Kolab has not announced any non-RSA roadmap. BSI TR-03116 (German TLS guidelines) does
 not yet mandate non-RSA for IMAP servers

## impact

Cyrus IMAP is the server that stores and serves email. the TLS cert on the IMAP
server is what stands between "email is private" and "email is readable in transit."

- factor the Cyrus IMAP server's RSA-2048 certificate (available from a TLS handshake
 scan), impersonate the server to any IMAP client. intercept email being fetched by
 mail clients. IMAP protocol reveals message content, folder structure, read/unread
 status, and all metadata
- for Kolab/German government deployments: MitM IMAPS connections to the Cyrus server.
 intercept ministerial email, cabinet communications, Bundeswehr internal correspondence.
 the BSI-approved email infrastructure fails because the RSA cert is broken
- Cyrus replication (sync_client) uses TLS between IMAP servers. MitM the replication
 channel and you get a full copy of every email being replicated to the secondary server
- SASL EXTERNAL over IMAP TLS uses RSA client certificates (same attack as openldap-tls
 and postgresql-ssl). forge a client cert for any user's IMAP account, authenticate
 as that user, access their mailbox

## Code

`cyrus_tls_rsa.c` — `tls_init_serverengine()` (RSA cert/key loading, SASL EXTERNAL
client cert setup), `tls_start_servertls()` (TLS handshake, client cert DN extraction),
and notes on Kolab/German government deployment context. From `imap/tls.c` in the
Cyrus IMAP repository at cyrusimap.org.
