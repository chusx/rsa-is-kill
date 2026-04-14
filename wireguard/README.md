# WireGuard — Hardcoded Curve25519

**Source:** https://github.com/torvalds/linux  
**File:** `drivers/net/wireguard/noise.c`  
**License:** GPLv2

## what it does

WireGuard implements the Noise_IKpsk2 handshake protocol for key exchange. Every cryptographic operation is hardcoded to a fixed suite: Curve25519 for DH, ChaCha20-Poly1305 for AEAD, BLAKE2s for hashing. This is baked into the protocol name string itself.

## why it's broken by a poly-time factorization

- Curve25519 is an elliptic curve Diffie-Hellman scheme. While not RSA, it is equally broken by Shor's algorithm — a CRQC recovers the private key from the public key.
- There is **zero algorithm agility** in WireGuard. The handshake name `"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"` is a literal constant. Every DH call is `curve25519()` directly, with no abstraction layer.
- Key sizes (`NOISE_PUBLIC_KEY_LEN = 32`) are compile-time constants. A lattice-based KEM like ML-KEM requires different key sizes and a different API — you cannot drop it in.
- The pre-shared-key (`psk`) field provides a classical mitigation (symmetric key can't be broken by Shor's) but the pre-shared key itself must be distributed securely, defeating the purpose of the key exchange.

## migration status

WireGuard upstream has no PQC plan. Some VPN providers (NordVPN, Mullvad) have added PQC by wrapping WireGuard in a separate ML-KEM tunnel — not by changing WireGuard itself.
