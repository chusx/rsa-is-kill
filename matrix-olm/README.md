# Matrix / Olm — Curve25519 X3DH End-to-End Encryption

**Source:** https://gitlab.matrix.org/matrix-org/olm  
**Files:** `src/session.cpp`, `include/olm/ratchet.hh`  
**License:** Apache-2.0

## what it does

Olm is the end-to-end encryption library used by Element (the largest Matrix client) and all Matrix homeservers. It implements X3DH (Extended Triple Diffie-Hellman) for session setup and a Double Ratchet for forward secrecy. Megolm is the variant used for multi-party room encryption. Both use Curve25519 throughout.

## why is this hella bad

- Every X3DH operation (`DH1`, `DH2`, `DH3`, `DH4`) is Curve25519 ECDH. Shor's algorithm breaks Curve25519 the same way it breaks RSA.
- `CURVE25519_KEY_LENGTH = 32` is hardcoded in the ratchet struct. ML-KEM-768 ciphertexts are 1088 bytes — a fundamentally different wire format requiring a new protocol version.
- "Harvest now, decrypt later" applies here: anyone storing encrypted Matrix messages today (any server-side logging, any state actor intercepting traffic) can decrypt them once a CRQC exists.
- There are millions of Matrix users. The default client (Element) has 10M+ downloads. Every DM ever sent is Curve25519-protected.
- Matrix has an open GitHub issue (#975) for quantum resistance since 2020. No implementation exists.

## migration status

Open issue since 2020. Signal has shipped PQXDH (hybrid Kyber+X25519). Matrix has not. No timeline.
