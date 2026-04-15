# samba-netlogon — RSA in Linux Windows-domain authentication (Samba AD)

**Repository:** git.samba.org 
**Industry:** Enterprise IT — Linux/Unix in Windows AD environments, Linux file servers 
**Algorithm:** RSA-2048 (KDC PKINIT certs, LDAP/SMB TLS server cert, domain CA) 

## What it does

Samba enables Linux and Unix systems to participate in Windows Active Directory
environments. A Samba AD DC acts as a full domain controller — KDC, LDAP, DNS,
SMB — for mixed Windows/Linux environments. Samba is used as an AD DC or domain
member at tens of thousands of organizations, particularly where running Windows
Server is cost-prohibitive.

Samba uses RSA for:
- **PKINIT** — the Heimdal KDC in Samba processes RSA-2048 certificates from
 smartcard logon and Windows Hello for Business. `source4/kdc/pkinit.c`
- **Samba domain CA** — `samba-tool domain provision` generates a self-signed
 RSA-2048 CA and issues RSA-2048 TLS certificates for all domain services
- **LDAP TLS** — the slapd-equivalent in Samba uses its RSA-2048 cert for all
 LDAP directory connections (domain clients, SSSD, etc.)
- **SMB3 over TLS** — SMB over QUIC (Windows 11 / Server 2022 feature) uses
 TLS with the Samba server's RSA-2048 certificate

The Samba PKINIT code uses Heimdal's hx509 library for X.509 certificate
verification. The GnuTLS backend is used for SMB3 TLS and LDAP TLS.
Neither hx509 nor GnuTLS has non-RSA algorithm support in deployed versions.

## Why it's stuck

- `samba-tool domain provision` has no `--cert-algorithm` flag. RSA-2048 is
 hardcoded as the provisioning certificate algorithm
- Heimdal hx509 (the X.509 library used for PKINIT) has no non-RSA algorithm OID support
- GnuTLS `NORMAL` priority string (used for Samba TLS) does not include any non-RSA
 cipher suite as of GnuTLS 3.8.x
- The Samba CA certificate is burned into the domain at provision time.
 Replacing it requires reprovisioning or a CA chain migration — neither is trivial
 in production AD environments

## impact

Samba AD DC is the domain controller for Linux-based AD environments. the RSA CA
it generates at provisioning is the root of trust for the entire domain.

- factor the Samba domain CA RSA-2048 key (the CA cert is in LDAP at
 CN=Configuration, readable by any domain user, same as ADCS). issue certificates
 for any domain user or computer. do PKINIT to get a Kerberos TGT as any user
 including domain admins. own the domain
- Samba PKINIT verifies RSA-2048 client certificates from smartcard logon.
 forge a certificate with the DN of any user, authenticate to the KDC, get a TGT.
 no smartcard needed
- SMB3 server certificate: factor it, impersonate the Samba file server. MitM every
 SMB3-with-TLS connection. intercept files being read and written, harvest NTLM
 hashes if any mixed-mode auth falls back to NTLM
- the Samba LDAP server cert is RSA-2048. MitM LDAP and you intercept all SSSD
 authentication requests, group membership lookups, and sudo policy queries for
 every Linux host joined to the domain

## Code

`samba_rsa_auth.c` — `samba_kdc_pkinit_verify_client()` (Heimdal hx509 RSA cert
verification for PKINIT smartcard auth), `samba_smb3_tls_setup()` (GnuTLS RSA cert
for SMB3 TLS), and inline notes on `samba-tool domain provision` generating RSA-2048
for the domain CA and all service certificates. From `source4/kdc/pkinit.c` and
related files on `git.samba.org`.
