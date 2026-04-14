/*
 * Source: Tor Project - https://gitlab.torproject.org/tpo/core/tor
 * File:   src/feature/relay/router.c
 * License: BSD-3-Clause
 *
 * Relevant excerpt: RSA identity key signs relay descriptors.
 * Every relay publishes a signed descriptor to the directory authorities.
 * The signature uses the relay's RSA-1024 identity key.
 */

char *
router_dump_router_to_string(routerinfo_t *router,
                             const crypto_pk_t *ident_key,   /* RSA-1024 */
                             const crypto_pk_t *tap_key,
                             const curve25519_keypair_t *ntor_keypair,
                             const ed25519_keypair_t *signing_keypair)
{
    /* Verify the RSA identity key matches what's stored in the routerinfo.
     * This RSA-1024 key IS the relay's identity on the network - its
     * fingerprint appears in consensus documents and is what clients
     * use to recognize and authenticate the relay. */
    if (!crypto_pk_eq_keys(ident_key, router->identity_pkey)) {
        log_warn(LD_BUG, "Tried to sign a router with a private key that "
                 "didn't match router's public key!");
        goto err;
    }

    /* Cross-certify TAP onion key with RSA identity key.
     * make_tap_onion_key_crosscert() calls crypto_pk_private_sign_digest()
     * which uses RSA-1024 PKCS#1 v1.5 signing.
     * This cross-cert ties the relay's circuit-layer keys to its identity. */
    if (tap_key && rsa_pubkey &&
        router->cache_info.signing_key_cert &&
        router->cache_info.signing_key_cert->signing_key_included) {
        uint8_t *tap_cc =
            make_tap_onion_key_crosscert(
                tap_key,
                &router->cache_info.signing_key_cert->signing_key,
                router->identity_pkey,    /* <-- RSA-1024 signs here */
                &tap_cc_len);
    }
    /* ... rest of descriptor assembly ... */
}

/*
 * The Tor relay consensus also lists each relay's RSA-1024 fingerprint,
 * e.g.:
 *   r PrivacyRepublic0 <base64-id> <base64-digest> 2026-04-14 ...
 *   s Fast Guard HSDir Running Stable V2Dir Valid
 *   v Tor 0.4.8.17
 *   id rsa1024 <fingerprint>    <-- RSA-1024 identity, still required
 *
 * Ed25519 identity was added in 0.2.7 but RSA-1024 remains mandatory.
 * As of 2026 both identities must be present; dropping RSA breaks
 * compatibility with ~5% of the network still running older versions.
 */
