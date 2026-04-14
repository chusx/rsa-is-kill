# strongSwan — RSA X.509 Certificate Verification (IKEv2)

**Source:** https://github.com/strongswan/strongswan  
**File:** `src/libstrongswan/plugins/x509/x509_cert.c`  
**License:** GPLv2

## what it does

strongSwan is the dominant open-source IPsec/IKEv2 VPN implementation on Linux. `issued_by()` verifies that a certificate was signed by a given CA — this is called during IKEv2 AUTH exchange when a VPN peer presents its certificate for authentication.

## why is this hella bad

- The signature verification dispatches on an OID parsed from the certificate's `AlgorithmIdentifier`. The default build knows RSA and ECDSA OIDs. PQC OIDs (e.g. ML-DSA's `2.16.840.1.101.3.4.3.17`) are `SIGN_UNKNOWN` unless the `oqs` plugin is loaded.
- The `oqs` plugin is not packaged by any major Linux distribution. Enterprises using `strongswan` from apt/yum/zypper get RSA-only.
- IKEv2 has no standardized PQC authentication method. `draft-ietf-ipsecme-ikev2-pqc-auth` is a draft as of 2026 — not yet an RFC. Even if strongSwan supports it, peers need to support it too.
- A CRQC can forge the RSA certificate of any VPN gateway, impersonate it, and perform a man-in-the-middle on every corporate VPN connection.

## migration status

strongSwan has experimental PQC support via the `oqs` plugin (liboqs). Not available in distro packages, not standardized in IKEv2, not deployed in practice.
