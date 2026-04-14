# DNSSEC / BIND9 — RSA Zone Signing

**Source:** https://github.com/isc-projects/bind9  
**File:** `lib/dns/opensslrsa_link.c`  
**License:** MPL-2.0

## what it does

BIND9 is the most deployed DNS server software. `opensslrsa_link.c` implements the RSA backend for DNSSEC zone signing. Every signed DNS record (A, AAAA, MX, CNAME, TXT...) is signed with an RSA key. Algorithm numbers 5, 7, 8, and 10 in the IANA registry are all RSA variants.

## impact

the DNS root KSK is RSA-2048. it signs the root zone, which signs all TLD zones (.com, .net, .org, etc.), which sign everything under them. DNS is literally how every computer on the internet finds every other computer.

- forge the root KSK and every DNSSEC-validated response on the internet is forgeable. redirect anyone anywhere
- DANE stores TLS certificate fingerprints in DNS and depends on DNSSEC for integrity. break DNSSEC and DANE's certificate pinning collapses with it
- RSA-1024 ZSKs are still in production use across thousands of zones. already classically weak and definitely quantum-broken
- EVP_SignFinal calling RSA_sign() is the trust foundation for the entire signed DNS tree. the whole thing falls from the root down
## migration status

Verisign has published research on SLH-DSA for DNSSEC (with MTL mode to reduce signature size). IETF has drafts. No production deployment, no IANA algorithm number assigned. Root KSK rollover is a years-long process.
