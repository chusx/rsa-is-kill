/*
 * master_key_load_ceremony.c
 *
 * IBM ICSF (Integrated Cryptographic Service Facility) Master-Key
 * Load / Install path on z/OS via Crypto Express 8S (CEX8S)
 * or TKE (Trusted Key Entry) workstation. The "Master Key" is the
 * top of the key hierarchy; it wraps every DES/AES/PKA key in the
 * CKDS/PKDS/TKDS. The TKE-to-CEX channel uses RSA-2048 for
 * authenticated key transport.
 *
 * Master-key ceremonies use split knowledge: two or three TKE
 * smart-card holders must participate. The MK parts are RSA-
 * wrapped from TKE -> CEX. If the CEX transport RSA key is
 * factored, an attacker recovers the AES-256 Master Key from
 * a recorded ceremony transcript — and from that, derives
 * every key in every CKDS/PKDS on every LPAR sharing that CEX.
 *
 * ~80% of global Tier-1/Tier-2 bank core-banking (CICS/IMS) and
 * payment-switch workloads run on z/OS + ICSF + CEX.
 */

#include <stdint.h>
#include <string.h>
#include "icsf.h"

/* The TKE workstation's identity cert (RSA-2048, signed by
 * the local TKE CA, which chains to IBM's Crypto Module CA).
 * This cert is presented to CEX during the key-load handshake. */
extern const uint8_t TKE_WORKSTATION_CERT[];
extern size_t TKE_WORKSTATION_CERT_LEN;

/* CEX card's transport key — RSA-2048, generated at card
 * first-boot and never rotated without card re-initialization. */
extern const uint8_t CEX_TRANSPORT_PUB[384];

enum mk_type {
    MK_DES  = 1,   /* legacy DES master key (SYM-MK)        */
    MK_AES  = 2,   /* AES master key (AES-MK)               */
    MK_PKA  = 3,   /* PKA (asymmetric) master key            */
    MK_HMAC = 4,   /* HMAC master key                        */
};

/* A single MK part, contributed by one smart-card holder.
 * Three parts XOR'd = the full 256-bit master key. */
struct mk_part {
    enum mk_type type;
    uint8_t      part_index;        /* 1..3 (split-knowledge)    */
    uint8_t      value[32];         /* AES-256 key part          */
    uint8_t      part_hash[32];     /* verification pattern (VP) */
    char         holder_id[16];     /* TKE card CN               */
};

/* The mk_part is RSA-OAEP wrapped with CEX_TRANSPORT_PUB before
 * traveling the TKE -> CEX USB/Ethernet link. An intercepted
 * session yields 3 ciphertexts; factoring the CEX transport key
 * recovers all 3 parts -> XOR -> full MK. */
struct mk_part_wrapped {
    uint8_t  rsa_ciphertext[256];     /* RSA-OAEP(part.value)   */
    uint8_t  tke_sig[256];            /* RSA-PSS signed session  */
    uint8_t  tke_cert[2048]; size_t tke_cert_len;
};

int cex_receive_mk_part(const struct mk_part_wrapped *w,
                        struct mk_assembly *a)
{
    /* Verify TKE identity cert chains to IBM Crypto Module CA. */
    if (x509_chain_verify(w->tke_cert, w->tke_cert_len,
            IBM_CRYPTO_MODULE_CA, IBM_CRYPTO_MODULE_CA_LEN))
        return ICSF_TKE_CHAIN;

    /* Verify session signature. */
    uint8_t h[32]; sha256(w->rsa_ciphertext, 256, h);
    if (verify_with_cert(w->tke_cert, w->tke_cert_len,
                         h, w->tke_sig, 256))
        return ICSF_TKE_SIG;

    /* RSA-OAEP decrypt using CEX private key (never leaves
     * the CEX card's tamper-responsive boundary). */
    uint8_t part_value[32]; size_t plen = 32;
    if (cex_rsa_oaep_decrypt(w->rsa_ciphertext, 256,
                             part_value, &plen))
        return ICSF_UNWRAP;

    /* XOR into the accumulator. */
    for (int i = 0; i < 32; ++i) a->accum[i] ^= part_value[i];
    a->parts_received++;
    if (a->parts_received == 3) {
        /* All three parts; install as NEW MK in the "new
         * master key register", pending ICSF SET MASTER KEY
         * command to promote it to CURRENT. */
        return cex_install_new_mk(a->type, a->accum);
    }
    return ICSF_NEED_MORE_PARTS;
}

/* =========================================================
 *  After MK install, every key in CKDS/PKDS is (re-)wrapped
 *  under MK. ICSF CSFKRC2 (Key Record Create) and CSFKRR2
 *  (Key Record Read) use AES key-wrap (RFC 3394) with MK as
 *  the KEK. Possession of MK = possession of every bank key.
 * ========================================================= */

/* ---- Harvest-Now-Decrypt-Now on the ceremony transcript --
 *
 *  1. Record TKE->CEX session (USB/Ethernet tap or insider
 *     with access to ceremony room network).
 *  2. Extract CEX_TRANSPORT_PUB (it's in the TKE handshake,
 *     or from the card's profile exported via ICSF query).
 *  3. Factor the RSA-2048 modulus.
 *  4. OAEP-decrypt 3 ciphertexts -> XOR -> full AES-256 MK.
 *  5. Read CKDS from z/OS spool/dataset (authorized read,
 *     or from a DR backup tape) -> unwrap every key.
 *  6. Derive: ATM PIN keys, SWIFT messaging keys, VISA/MC
 *     zone-master keys, ACH encryption keys, STP cert keys.
 *  The global financial-system key hierarchy collapses.
 *
 *  Recovery: new MK ceremony + CKDS reencipher (ICSF
 *  CSFKRW2) across every dataset. Requires coordinated
 *  downtime on every LPAR sharing the CEX. Banks plan
 *  18-24 months for an MK rotation; emergency = weeks
 *  with degraded operations.
 * --------------------------------------------------------- */
