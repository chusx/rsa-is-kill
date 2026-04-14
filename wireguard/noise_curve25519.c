/*
 * Source: Linux kernel - https://github.com/torvalds/linux
 * File:   drivers/net/wireguard/noise.c
 * License: GPLv2
 *
 * Relevant excerpt: WireGuard's Noise_IKpsk2 handshake is hardcoded
 * to Curve25519 + ChaCha20-Poly1305 + BLAKE2s.  The algorithm suite
 * is baked into the protocol name string and into every DH call site.
 * There is no negotiation, no algorithm field, no upgrade path.
 * Changing the KEM requires a new protocol version incompatible with
 * every existing WireGuard peer.
 */

/* Protocol identifier - algorithm names are literals, not variables */
static const u8 handshake_name[37] __nonstring =
    "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
static const u8 identifier_name[34] __nonstring =
    "WireGuard v1 zx2c4 Jason@zx2c4.com";

/*
 * mix_dh: performs a Diffie-Hellman step and mixes the result into
 * the chaining key.  curve25519() is called directly - not via any
 * abstraction layer that could be swapped for ML-KEM.
 */
static bool mix_dh(u8 chaining_key[NOISE_HASH_LEN],
                   u8 key[NOISE_SYMMETRIC_KEY_LEN],
                   const u8 private[NOISE_PUBLIC_KEY_LEN],
                   const u8 public[NOISE_PUBLIC_KEY_LEN])
{
    u8 dh_calculation[NOISE_PUBLIC_KEY_LEN];
    if (unlikely(!curve25519(dh_calculation, private, public)))
        return false;
    mix_key(chaining_key, key, dh_calculation, NOISE_PUBLIC_KEY_LEN);
    memzero_explicit(dh_calculation, NOISE_PUBLIC_KEY_LEN);
    return true;
}

/*
 * Initiator handshake (first message).
 * Every DH operation calls curve25519() directly.
 * Key sizes (NOISE_PUBLIC_KEY_LEN = CURVE25519_KEY_SIZE = 32) are
 * compile-time constants - a lattice KEM would need different sizes.
 */
bool wg_noise_handshake_create_initiation(struct message_handshake_initiation *dst,
                                          struct wg_peer *peer)
{
    /* ephemeral keypair - always Curve25519 */
    curve25519_generate_secret(handshake->ephemeral_private);
    curve25519_generate_public(dst->unencrypted_ephemeral,
                               handshake->ephemeral_private);
    mix_dh(chaining_key, NULL,
           handshake->ephemeral_private,
           handshake->remote_static);

    /* static DH */
    mix_dh(chaining_key, key,
           handshake->static_identity->static_private,
           handshake->remote_static);

    /* precomputed static-static DH (done at peer creation time) */
    curve25519(peer->handshake.precomputed_static_static,
               peer->handshake.static_identity->static_private,
               peer->handshake.remote_static);
}
