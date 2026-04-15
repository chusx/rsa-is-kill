# GnuPG — RSA Key Generation

**Source:** https://github.com/gpg/gnupg 
**File:** `g10/keygen.c` 
**License:** GPLv3

## what it does

GnuPG's key generation code handles interactive and batch creation of OpenPGP keypairs. Modern GnuPG (2.3+) defaults to Ed25519/Cv25519, but RSA-3072 remains fully supported and is the default in many enterprise and compliance contexts.

## impact

GnuPG is the web of trust. every RSA signature on every key, every signed message, every package repository is retroactively forgeable once the key falls.

- once a classical poly-time factoring algorithm exists, RSA-1024 through RSA-4096 all fall together. key size changes only the constant, not the asymptotic
- every web-of-trust signature ever made with an RSA key is retroactively forgeable. decades of identity verification built on GPG collapses
- Debian, RPM, and Arch package repositories use RSA GPG keys for package signing. every system that hasn't rotated off RSA is trusting a root that becomes forgeable
- Ed25519 keys are unaffected (the attack is against factoring, not discrete log), so the GnuPG 2.3 default migration is a real defense — but the installed base is overwhelmingly still RSA
