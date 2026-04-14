# GnuPG — RSA Key Generation

**Source:** https://github.com/gpg/gnupg  
**File:** `g10/keygen.c`  
**License:** GPLv3

## what it does

GnuPG's key generation code handles interactive and batch creation of OpenPGP keypairs. Modern GnuPG (2.3+) defaults to Ed25519/Cv25519, but RSA-3072 remains fully supported and is the default in many enterprise and compliance contexts.

## why is this hella bad

- RSA-3072 provides ~128 classical security bits and **0 post-quantum bits**. The `get_keysize_range()` function offers RSA-1024 through RSA-4096 — none of which survive Shor's algorithm.
- Every web-of-trust signature ever made with an RSA key is retroactively forgeable. Identity verification built on RSA GPG keys collapses.
- No stable GnuPG release supports any NIST PQC finalist. The OpenPGP WG has a draft for hybrid Kyber+Dilithium keys, but it is not merged into GnuPG.
- Package repository signing (Debian, RPM, Arch) relies on RSA GPG keys. Every system that hasn't rotated to Ed25519 is trusting an RSA root that becomes forgeable.
- `DEFAULT_STD_KEY_PARAM = "ed25519/cert,sign+cv25519/encr"` shows GnuPG knows better — but this only helps new keys, not the billions of existing RSA keys in the wild.

## migration status

OpenPGP PQC draft (Kyber + Dilithium) exists at IETF but is not finalized. No production GnuPG release includes it.
