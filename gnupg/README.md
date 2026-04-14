# GnuPG — RSA Key Generation

**Source:** https://github.com/gpg/gnupg  
**File:** `g10/keygen.c`  
**License:** GPLv3

## what it does

GnuPG's key generation code handles interactive and batch creation of OpenPGP keypairs. Modern GnuPG (2.3+) defaults to Ed25519/Cv25519, but RSA-3072 remains fully supported and is the default in many enterprise and compliance contexts.

## impact

GnuPG is the web of trust. every RSA signature on every key, every signed message, every package repository is retroactively forgeable once the key falls.

- RSA-3072 gives about 128 bits of classical security and zero bits of post-quantum security. RSA-1024 through RSA-4096 are all equally dead to Shor's algorithm, the key size just changes the timeline
- every web-of-trust signature ever made with an RSA key is retroactively forgeable. decades of identity verification built on GPG collapses
- Debian, RPM, and Arch package repositories use RSA GPG keys for package signing. every system that hasn't rotated to Ed25519 is trusting an RSA root that becomes forgeable
- no stable GnuPG release supports any NIST PQC algorithm. the OpenPGP PQC hybrid draft exists at IETF but hasn't shipped
## migration status

OpenPGP PQC draft (Kyber + Dilithium) exists at IETF but is not finalized. No production GnuPG release includes it.
