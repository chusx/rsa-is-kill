# Tor — RSA-1024 Relay Identity Keys

**Source:** https://gitlab.torproject.org/tpo/core/tor  
**Files:** `src/lib/crypt_ops/crypto_rsa.h`, `src/feature/relay/router.c`  
**License:** BSD-3-Clause

## what it does

Every Tor relay has an RSA identity key. The SHA-1 fingerprint of this key IS the relay's identity — it's how clients recognize relays in the consensus, how circuits are built, and how relays authenticate to directory authorities.

## impact

Tor relay identity keys are RSA-1024, published in the consensus directory. RSA-1024 is already classically weak with sufficient compute, so this is a present-day concern too, not just a future CRQC problem.

- recover any relay's RSA-1024 identity key, impersonate that relay to clients and other relays, inject yourself into circuits as a "known good" node
- RSA-1024 is classically breakable. nation-state adversaries with serious classical compute may already be attacking individual relay identity keys without any CRQC
- Tor directory authorities sign the consensus with RSA keys. forge the consensus and you can substitute relays, rewrite the network view, or make malicious relays appear trustworthy
- v2 hidden service .onion addresses are derived from RSA-1024 public keys. recover the private key and impersonate any v2 hidden service. v3 onion uses Ed25519, which is still ECDL-based and broken by Shor's algorithm on a CRQC anyway
## migration status

Ongoing Ed25519 migration. RSA-1024 mandatory until old relay versions die off. No PQC timeline.
