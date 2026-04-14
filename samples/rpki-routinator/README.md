# RPKI / Routinator — RSA BGP Routing Security

**Source:** https://github.com/NLnetLabs/rpki-rs  
**File:** `src/crypto/keys.rs`  
**License:** BSD-3-Clause

## what it does

RPKI (Resource Public Key Infrastructure) is the cryptographic layer that secures BGP routing. Route Origin Authorizations (ROAs) are signed certificates that say which AS is allowed to announce which IP prefix. Routinator is the most widely deployed RPKI validator (NLnetLabs, used by major ISPs and IXPs worldwide).

## why it's the most dangerous one on this list

This one has a unique property: **breaking it makes the internet less secure than having no security at all.**

- Every ROA is verified using `RSA_PKCS1_2048_8192_SHA256` — RSA only, hardcoded.
- A CRQC can forge ROAs — certificates that say "AS666 is authorized to announce 8.8.8.8/24".
- Route Origin Validation (ROV) will then **actively route traffic to the attacker** because the forged ROA makes the hijacked route look valid and the legitimate route look invalid.
- Without RPKI, a BGP hijack is detectable as an anomaly. With broken RPKI, it's a cryptographically authenticated reroute that passes every check.
- The five RIR trust anchors (ARIN, RIPE, APNIC, LACNIC, AFRINIC) are RSA. Forging any of them compromises the entire address space under that RIR.

## migration status

No PQC algorithm OID assigned by IANA for RPKI. Migration requires updating all five RIR hierarchies simultaneously. APNIC has published research; no deployment timeline exists.
