# Tor — RSA-1024 Relay Identity Keys

**Source:** https://gitlab.torproject.org/tpo/core/tor  
**Files:** `src/lib/crypt_ops/crypto_rsa.h`, `src/feature/relay/router.c`  
**License:** BSD-3-Clause

## what it does

Every Tor relay has an RSA identity key. The SHA-1 fingerprint of this key IS the relay's identity — it's how clients recognize relays in the consensus, how circuits are built, and how relays authenticate to directory authorities.

## why is this hella bad

- `PK_BYTES = 1024/8` — **RSA-1024**. This is classically broken (NIST deprecated in 2013). Quantumly obliterated.
- The relay descriptor is signed with this key via `crypto_pk_private_sign_digest()`. Forge the signature → impersonate any relay.
- A CRQC operator controlling forged relay identities can run a fully authenticated Sybil attack on Tor: they can be selected as guards, middles, and exits simultaneously, de-anonymizing users without any traffic analysis.
- Tor added Ed25519 identity keys in 0.2.7 but **RSA-1024 is still mandatory** for backward compatibility with older relays. A relay that drops its RSA-1024 key cannot communicate with ~5% of the network.
- There are ~7,000 active Tor relays. A CRQC could forge all of their identities simultaneously.

## migration status

Ongoing Ed25519 migration. RSA-1024 mandatory until old relay versions die off. No PQC timeline.
