# DNSSEC / BIND9 — RSA Zone Signing

**Source:** https://github.com/isc-projects/bind9  
**File:** `lib/dns/opensslrsa_link.c`  
**License:** MPL-2.0

## what it does

BIND9 is the most deployed DNS server software. `opensslrsa_link.c` implements the RSA backend for DNSSEC zone signing. Every signed DNS record (A, AAAA, MX, CNAME, TXT...) is signed with an RSA key. Algorithm numbers 5, 7, 8, and 10 in the IANA registry are all RSA variants.

## why it matters

- The DNS root zone KSK is **RSA-2048**. It signs the root zone, which signs all TLD zones (.com, .net, .org, etc.), which sign everything under them.
- If the root KSK is forged, every DNSSEC-validated response on the internet is forgeable. DNS is the phonebook of the internet.
- **DANE** (DNS-based Authentication of Named Entities) stores certificate fingerprints in DNS. DNSSEC protects DANE. If DNSSEC is broken, DANE is broken — the TLS certificate pinning that DANE provides collapses.
- RSA-1024 ZSKs are still in production use across thousands of zones. These are classically weak AND quantum-broken.
- `EVP_SignFinal()` calling into `RSA_sign()` is the entire trust foundation of the signed web.

## migration status

Verisign has published research on SLH-DSA for DNSSEC (with MTL mode to reduce signature size). IETF has drafts. No production deployment, no IANA algorithm number assigned. Root KSK rollover is a years-long process.
