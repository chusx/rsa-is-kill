/*
 * jtids_key_load.c
 *
 * Link-16 / MIDS (Multifunctional Information Distribution
 * System) JTIDS (Joint Tactical Information Distribution System)
 * key management. Link-16 carries real-time tactical data
 * (air picture, targeting, IFF) between NATO fighters,
 * AWACS, Aegis destroyers, and Patriot batteries.
 *
 * JTIDS uses a TRANSEC (transmission security) key loaded from
 * the KGV-11 / AN/CYZ-10 (Simple Key Loader, SKL). The SKL
 * receives key fills from the EKMS (Electronic Key Management
 * System) which uses RSA-wrapped key-transport to push COMSEC
 * material to unit-level devices.
 *
 * A factored EKMS distribution RSA key exposes the TRANSEC
 * keys for every Link-16 net in a theater.
 */

#include <stdint.h>
#include <string.h>
#include "jtids.h"

extern const uint8_t EKMS_DIST_ROOT_PUB[384];     /* RSA-3072   */

struct key_fill {
    uint32_t  net_number;              /* Link-16 net (0-127)     */
    uint8_t   crypto_period;           /* hours until zeroize     */
    uint8_t   algorithm;               /* BATON / SAVILLE         */
    uint8_t   wrapped_key[256];        /* RSA-OAEP(TRANSEC key)   */
    uint8_t   ekms_cert[2048]; size_t ekms_cert_len;
    uint8_t   ekms_sig[384];
};

int skl_receive_fill(const struct key_fill *f)
{
    if (x509_chain_verify(f->ekms_cert, f->ekms_cert_len,
            EKMS_DIST_ROOT_PUB, sizeof EKMS_DIST_ROOT_PUB))
        return EKMS_CHAIN;
    uint8_t h[32];
    sha256_of(f, offsetof(struct key_fill, ekms_cert), h);
    if (verify_with_cert(f->ekms_cert, f->ekms_cert_len,
                         h, f->ekms_sig, sizeof f->ekms_sig))
        return EKMS_SIG;
    /* Unwrap TRANSEC key. */
    uint8_t tk[32]; size_t tlen = 32;
    crypto_module_rsa_oaep_decrypt(f->wrapped_key, 256, tk, &tlen);
    return skl_store_key(f->net_number, f->algorithm, tk, tlen);
}

/* ---- Theater-level SIGINT / targeting impact ---------------
 *  EKMS_DIST_ROOT factored:
 *    Recover TRANSEC keys for every Link-16 net. Decrypt
 *    real-time air picture + weapons targeting. Also inject
 *    spoofed Link-16 messages (false tracks, false IFF) that
 *    pass TRANSEC authentication.
 * --------------------------------------------------------- */
