# RPKI / Routinator — RSA BGP Routing Security

**Source:** https://github.com/NLnetLabs/rpki-rs  
**File:** `src/crypto/keys.rs`  
**License:** BSD-3-Clause

## what it does

RPKI (Resource Public Key Infrastructure) is the cryptographic layer that secures BGP routing. Route Origin Authorizations (ROAs) are signed certificates that say which AS is allowed to announce which IP prefix. Routinator is the most widely deployed RPKI validator (NLnetLabs, used by major ISPs and IXPs worldwide).

## impact

RPKI is BGP route origin validation, the mechanism that prevents BGP hijacking. it's all RSA. when it breaks it doesn't just stop working, it actively makes things worse.

- forge Route Origin Authorizations for any IP prefix. tell the internet that your ASN is authorized to announce 8.8.8.8/24, or 1.0.0.0/8, or any IP space you want
- ISPs doing route origin validation will actively prefer your forged route because it has a valid ROA. without RPKI, a BGP hijack is an anomaly. with broken RPKI, it's a cryptographically authenticated reroute that passes every check
- forge any of the five RIR trust anchors (ARIN, RIPE, APNIC, LACNIC, AFRINIC) and rewrite the entire validated route origin database for that region's address space
- the whole RPKI manifest and CRL chain is RSA. it all falls together
## migration status

No PQC algorithm OID assigned by IANA for RPKI. Migration requires updating all five RIR hierarchies simultaneously. APNIC has published research; no deployment timeline exists.
