# WireGuard — Hardcoded Curve25519

**Source:** https://github.com/torvalds/linux  
**File:** `drivers/net/wireguard/noise.c`  
**License:** GPLv2

## what it does

WireGuard implements the Noise_IKpsk2 handshake protocol for key exchange. Every cryptographic operation is hardcoded to a fixed suite: Curve25519 for DH, ChaCha20-Poly1305 for AEAD, BLAKE2s for hashing. This is baked into the protocol name string itself.

## impact

WireGuard uses Curve25519 for key exchange. Curve25519 is an elliptic curve, and elliptic curve discrete log is broken by Shor's algorithm. the static public keys are exchanged in handshakes and often stored in peer configs indefinitely.

- derive the static private key from the static public key. impersonate either endpoint to the other. inject into the WireGuard tunnel
- WireGuard is deployed as corporate VPN, cloud inter-node networking, and Kubernetes CNI overlay. MitM the tunnel and you're inside the network
- WireGuard static keys are long-lived and rarely rotated. HNDL: capture handshakes now, factor the Curve25519 keys later, retroactively decrypt all historical session traffic
- there's no PQC mode in the WireGuard protocol spec. adding it requires a protocol version bump and simultaneous update of every peer
## migration status

WireGuard upstream has no PQC plan. Some VPN providers (NordVPN, Mullvad) have added PQC by wrapping WireGuard in a separate ML-KEM tunnel — not by changing WireGuard itself.
