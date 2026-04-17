# Tor — RSA-1024 Relay Identity Keys

**Source:** https://gitlab.torproject.org/tpo/core/tor 
**Files:** `src/lib/crypt_ops/crypto_rsa.h`, `src/feature/relay/router.c` 
**License:** BSD-3-Clause

## what it does

Every Tor relay has an RSA identity key. The SHA-1 fingerprint of this key IS the relay's identity — it's how clients recognize relays in the consensus, how circuits are built, and how relays authenticate to directory authorities.

## impact

Tor relay identity keys are RSA-1024, published in the consensus directory. RSA-1024 is already classically weak with sufficient compute, so this is a present-day concern even before the new factoring attack lands.

- recover any relay's RSA-1024 identity key, impersonate that relay to clients and other relays, inject yourself into circuits as a "known good" node
- RSA-1024 is classically breakable. nation-state adversaries with serious classical compute may already be attacking individual relay identity keys
- Tor directory authorities sign the consensus with RSA keys. forge the consensus and you can substitute relays, rewrite the network view, or make malicious relays appear trustworthy
- v2 hidden service .onion addresses are derived from RSA-1024 public keys. recover the private key and impersonate any v2 hidden service. v3 onion moved to Ed25519 (ECDLP-based) which is NOT affected by a factoring break — that migration is what saves v3 here
