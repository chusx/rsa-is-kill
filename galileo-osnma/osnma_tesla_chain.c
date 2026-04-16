/*
 * osnma_tesla_chain.c
 *
 * Galileo Open Service Navigation Message Authentication (OSNMA)
 * TESLA key-chain verification. OSNMA authenticates Galileo
 * navigation messages so receivers can reject spoofed signals.
 * The TESLA root key is RSA-2048 signed by the Galileo Service
 * Provider (GSC, Fucino/Oberpfaffenhofen).
 *
 * If the OSNMA RSA root is factored, the attacker can forge
 * the TESLA chain and spoof authenticated Galileo signals
 * that pass OSNMA verification — defeating the anti-spoofing
 * upgrade designed specifically to prevent GPS-spoofing attacks.
 */

#include <stdint.h>
#include <string.h>
#include "osnma.h"

extern const uint8_t OSNMA_MERKLE_ROOT_PUB[384];  /* RSA-2048   */

struct osnma_dsmkroot {
    uint8_t   pkid;                    /* Public Key ID           */
    uint8_t   pk_type;                 /* 1=ECDSA-P256, 4=RSA    */
    uint8_t   pk[256];                 /* DER-encoded             */
    uint8_t   merkle_proof[128];       /* intermediate hashes     */
    uint8_t   rsa_sig[256];           /* RSA-SHA256 over PK      */
};

int osnma_verify_root_key(const struct osnma_dsmkroot *r)
{
    /* Verify the root public key against the Merkle tree
     * root (published in OSNMA SIS ICD). */
    uint8_t h[32];
    sha256(r->pk, 256, h);
    if (!merkle_verify(r->merkle_proof, 128, h,
                       OSNMA_MERKLE_ROOT_PUB, 384))
        return OSNMA_MERKLE;

    /* RSA signature over the TESLA root key. */
    sha256(r->pk, sizeof r->pk, h);
    if (rsa_pkcs1v15_verify_sha256(
            OSNMA_MERKLE_ROOT_PUB, 384,
            (uint8_t[]){1,0,1}, 3, h, 32,
            r->rsa_sig, sizeof r->rsa_sig))
        return OSNMA_SIG;

    return osnma_install_tesla_root(r->pk, r->pk_type);
}

/* ---- GNSS spoofing at authenticated level ------------------
 *  OSNMA root factored:
 *    Sign a forged TESLA chain; spoof authenticated Galileo
 *    signals. Receivers running OSNMA report "authenticated
 *    position" that is attacker-controlled. Affects:
 *      * Maritime (e-navigation, ECDIS)
 *      * Aviation (SBAS/GBAS approaches)
 *      * Autonomous vehicles (HD-map alignment)
 *      * Financial timestamping (MiFID II, FINRA CAT)
 *      * Telecom (5G synchronization via PTP-over-GNSS)
 *    Recovery: ESA/GSA rotates OSNMA PKI + every receiver's
 *    trust store updated. GNSS receivers in vehicles and
 *    infrastructure have multi-year replacement cycles.
 * --------------------------------------------------------- */
