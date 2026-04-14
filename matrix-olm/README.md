# Matrix / Olm — Curve25519 X3DH End-to-End Encryption

**Source:** https://gitlab.matrix.org/matrix-org/olm  
**Files:** `src/session.cpp`, `include/olm/ratchet.hh`  
**License:** Apache-2.0

## what it does

Olm is the end-to-end encryption library used by Element (the largest Matrix client) and all Matrix homeservers. It implements X3DH (Extended Triple Diffie-Hellman) for session setup and a Double Ratchet for forward secrecy. Megolm is the variant used for multi-party room encryption. Both use Curve25519 throughout.

## impact

Matrix device keys are long-lived and device public keys are synced to the homeserver where anyone in a room can see them. every X3DH key exchange is Curve25519, which Shor's algorithm breaks.

- forge any device's identity key, publish a fake device to the homeserver, get accepted into encrypted rooms as that device. decrypt messages intended for the real device
- cross-signing lets users mark each other's devices as verified. forge the cross-signing RSA key and mark any malicious device as "verified" in anyone's account
- HNDL: capture Matrix traffic now, factor the Curve25519 keys later, retroactively decrypt all historical encrypted messages. every DM ever sent is exposed
- Matrix has had an open GitHub issue (#975) for quantum resistance since 2020. Signal shipped PQXDH. Matrix has not
## migration status

Open issue since 2020. Signal has shipped PQXDH (hybrid Kyber+X25519). Matrix has not. No timeline.
