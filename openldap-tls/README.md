# openldap-tls — RSA client certs for LDAP directory authentication

**Repository:** git.openldap.org (not GitHub)  
**Industry:** Enterprise IT, Linux identity management, corporate directories  
**Algorithm:** RSA-2048 TLS server and client certificates  
**PQC migration plan:** None — OpenLDAP has no PQC TLS support; Go's crypto/tls PQC is in Go 1.24+ but OpenLDAP uses OpenSSL

## What it does

OpenLDAP's slapd is the open-source LDAP server used by Linux enterprises as their
directory service. It is also the LDAP backend embedded in Fedora 389-DS, Apple Open
Directory (historically), and numerous appliances.

SASL EXTERNAL is the LDAP authentication mechanism where the TLS client certificate
is the credential. The client presents an RSA-2048 certificate during the TLS handshake,
and slapd extracts the subject DN and maps it to an LDAP identity.

Used for:
- **LDAP administrator authentication** — "Directory Manager" authentication via RSA client cert instead of password
- **Service account LDAP binding** — applications authenticate to LDAP with a certificate (no password in config)
- **Slapd replication** — syncrepl between provider and consumer uses TLS mutual auth with RSA certs
- **Linux SSSD + LDAP** — SSSD uses LDAP for user/group lookups; TLS protects the channel
- **Kubernetes LDAP auth** — dex and similar OIDC bridges authenticate to LDAP with TLS

The slapd server certificate (RSA-2048) authenticates the directory server to clients.
The replication RSA certificate authenticates the replica to the provider.
Both are issued by the enterprise CA (typically ADCS or a Linux CA).

## Why it's stuck

- OpenLDAP uses OpenSSL for TLS. OpenSSL has no production ML-KEM/ML-DSA cipher suite
  fully integrated in released versions (as of OpenSSL 3.3)
- LDAP certificate profiles (RFC 4513) specify X.509 v3 with RSA or ECDSA.
  No PQC algorithm is defined for LDAP client certificates in any RFC
- slapd configuration (`TLSCertificateFile`, `TLSCertificateKeyFile`) expects PEM
  RSA/EC keys; there is no `TLSCertificateAlgorithm` option for PQC
- Enterprise LDAP deployments use certificates issued by enterprise CAs (ADCS, etc.)
  which don't support PQC (see adcs-windows/)

## impact

LDAP is the identity backbone for most corporate Linux environments. SASL EXTERNAL
means the RSA certificate IS the credential. forge it and you are the identity.

- forge a TLS client certificate for "cn=Directory Manager" (the LDAP superuser).
  slapd extracts the subject DN, matches it to the superuser account, grants full
  directory access. read all user credentials, modify any account, add arbitrary
  LDAP entries, or delete the entire directory
- forge the replication client certificate. connect to any slapd provider pretending
  to be a legitimate consumer. trigger a full sync, inject forged LDAP entries that
  replicate to every consumer in the topology
- SSSD caches LDAP user lookups for Linux PAM authentication. compromise the LDAP
  directory via forged SASL EXTERNAL, insert a new user or modify group memberships,
  and Linux hosts that authenticate against this LDAP will trust the changes on next
  cache refresh
- the slapd server RSA certificate is what clients use to verify they're connecting to
  the real directory server. forge it and MitM the LDAP connection for all clients
  doing ldaps:// connections, harvesting bind credentials (passwords) from
  applications that authenticate with simple bind over LDAP TLS

## Code

`openldap_sasl_tls.c` — `tlso_ctx_init()` (RSA cert/key loading, SSL_VERIFY_PEER for
SASL EXTERNAL), `slap_sasl_external()` (certificate DN to LDAP identity mapping), and
inline slapd.conf example showing replication TLS RSA certificate configuration.
From `libraries/libldap/tls_o.c` and `servers/slapd/sasl.c` on `git.openldap.org`.
