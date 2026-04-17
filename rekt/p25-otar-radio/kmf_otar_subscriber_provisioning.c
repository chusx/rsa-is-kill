/*
 * kmf_otar_subscriber_provisioning.c
 *
 * TIA-102 Key Management Facility (KMF) subscriber-unit provisioning
 * and Over-the-Air-Rekey (OTAR) envelope authentication. This is the
 * subscriber-unit (SU) side — runs on the radio's SoC (Motorola APX,
 * L3Harris XL/XG, JVCKenwood NX series) with a FIPS 140-2 Level 3
 * crypto module.
 *
 * References: TIA-102.AACA (OTAR), TIA-102.AACD (Link Layer Auth),
 * TIA-102.AACE (identity binding).
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include "p25_su.h"
#include "rsa_pss.h"
#include "rsa_oaep.h"
#include "aes_keywrap.h"

/* Vendor + agency trust anchors burned into the radio at factory
 * and re-bindable at KMF provisioning ceremony. */
extern const uint8_t VENDOR_FW_ROOT_PUB[512];     /* RSA-4096 */
extern const uint8_t AGENCY_KMF_ROOT_PUB[384];    /* RSA-3072 */


/* =========================================================
 *  1. Radio firmware self-verify at power-on
 * ========================================================= */

struct su_fw_manifest {
    char      vendor[16];
    char      model[16];
    char      build[32];
    uint32_t  rollback_idx;
    uint8_t   rf_baseband_sha256[32];
    uint8_t   crypto_core_sha256[32];
    uint8_t   codeplug_sha256[32];
    uint8_t   sig[512];
};

int su_fw_self_verify(void)
{
    struct su_fw_manifest *m = flash_read_manifest();
    if (m->rollback_idx < otp_read_rollback()) return ERR_ROLLBACK;

    uint8_t h[32];
    sha256_partition(PART_CRYPTO, h);
    if (memcmp(h, m->crypto_core_sha256, 32)) return ERR_CORRUPT;

    sha256_of(m, offsetof(struct su_fw_manifest, sig), h);
    return rsa_pss_verify_sha256(
        VENDOR_FW_ROOT_PUB, sizeof VENDOR_FW_ROOT_PUB,
        (uint8_t[]){0x01,0x00,0x01}, 3,
        h, 32, m->sig, sizeof m->sig);
}


/* =========================================================
 *  2. Subscriber-unit enrollment at the KMF
 *
 *  The radio generates an RSA-3072 keypair inside its crypto
 *  module. The KMF-presented provisioning cert (issued by agency
 *  CA) is chain-verified, and the radio's pubkey is signed into
 *  an SU-identity cert returned from the KMF. Private key never
 *  leaves the crypto module.
 * ========================================================= */

int su_enroll_at_kmf(const uint8_t *kmf_prov_cert, size_t cert_len,
                      uint8_t *issued_su_cert_out, size_t *out_len)
{
    /* 1. Verify KMF provisioning cert to agency root. */
    if (x509_chain_verify(kmf_prov_cert, cert_len,
                          AGENCY_KMF_ROOT_PUB,
                          sizeof AGENCY_KMF_ROOT_PUB) != 0)
        return ERR_KMF_CHAIN;

    /* 2. Generate keypair + CSR in crypto module. */
    crypto_module_rsa3072_keygen(SLOT_SU_IDENTITY);
    uint8_t csr[2048]; size_t csr_len;
    crypto_module_build_csr(SLOT_SU_IDENTITY,
                            su_radio_id_string(),
                            csr, sizeof csr, &csr_len);

    /* 3. Send CSR over the OTAR bearer to KMF; receive signed SU
     *    identity cert. Bearer runs on the P25 Packet Data Channel
     *    (PDCH) or via KMF-operated IP link at programming cradle. */
    if (otar_bearer_submit_csr(csr, csr_len,
                                issued_su_cert_out, out_len) != 0)
        return ERR_OTAR_TRANSPORT;

    /* 4. Re-verify the returned cert chains to agency root. */
    if (x509_chain_verify(issued_su_cert_out, *out_len,
                          AGENCY_KMF_ROOT_PUB,
                          sizeof AGENCY_KMF_ROOT_PUB) != 0)
        return ERR_ISSUED_CHAIN;

    crypto_module_install_cert(SLOT_SU_IDENTITY,
                                issued_su_cert_out, *out_len);
    return 0;
}


/* =========================================================
 *  3. OTAR envelope — TEK/KEK delivery
 *
 *  KMF wraps TEKs under a KEK (AES-256 key-wrap) and signs the
 *  envelope. Key-material confidentiality rides symmetric wrap;
 *  envelope authenticity rides KMF's RSA signature.
 *
 *  Under a factoring-break: the attacker forges a legitimate-looking
 *  KMF-signed OTAR envelope and substitutes a KEK they control.
 *  From that point the radio decrypts attacker-supplied TEKs as
 *  real; real traffic encrypted under those TEKs becomes
 *  recoverable.
 * ========================================================= */

struct otar_tek_envelope {
    uint32_t  kmf_serial;
    uint32_t  seq;                    /* monotonic per-radio */
    uint32_t  issued_ts;
    uint16_t  sln;                    /* Storage Location Number */
    uint16_t  algid;                  /* 0x84 = AES-256 */
    uint16_t  wrapped_tek_len;
    uint8_t   wrapped_tek[64];        /* AES-KW under KEK */
    uint8_t   kmf_cert[1536];
    size_t    cert_len;
    uint8_t   sig[384];               /* RSA-3072 PSS over the above */
};

static uint32_t last_kmf_seq_per_sln[256];

int su_apply_otar_tek(const struct otar_tek_envelope *env)
{
    if (env->seq <= last_kmf_seq_per_sln[env->sln & 0xff])
        return ERR_REPLAY;

    /* KMF cert → agency root */
    if (x509_chain_verify(env->kmf_cert, env->cert_len,
                          AGENCY_KMF_ROOT_PUB,
                          sizeof AGENCY_KMF_ROOT_PUB) != 0)
        return ERR_KMF_CHAIN;

    uint8_t n[384], e[4];
    size_t n_len, e_len;
    x509_extract_pub(env->kmf_cert, env->cert_len,
                     n, sizeof n, &n_len, e, sizeof e, &e_len);

    uint8_t h[32];
    sha256_of(env, offsetof(struct otar_tek_envelope, sig), h);
    if (rsa_pss_verify_sha256(n, n_len, e, e_len,
                              h, 32, env->sig, sizeof env->sig) != 0)
        return ERR_SIG;

    /* Unwrap the TEK under the pre-shared KEK in the crypto module. */
    uint8_t tek[32];
    size_t tek_len = sizeof tek;
    if (crypto_module_aes_unwrap(
            KEK_SLOT_FOR_SLN(env->sln),
            env->wrapped_tek, env->wrapped_tek_len,
            tek, &tek_len) != 0 || tek_len != 32)
        return ERR_UNWRAP;

    crypto_module_install_tek(env->sln, tek);
    secure_wipe(tek, sizeof tek);
    last_kmf_seq_per_sln[env->sln & 0xff] = env->seq;
    return 0;
}


/* =========================================================
 *  4. Link-Layer Authentication on registration (TIA-102.AACD)
 *
 *  Challenge-response with K shared between SU and AuC/KMF is
 *  the on-air loop. The *binding* that K-for-this-SU belongs to
 *  this agency is anchored in the RSA PKI above — without the
 *  asymmetric chain, the symmetric K is unplaced.
 * ========================================================= */

int su_lla_register(const uint8_t *auc_challenge, size_t chlen,
                     uint8_t *response_out, size_t *rlen)
{
    uint8_t K[32];
    crypto_module_load_k(K);
    hmac_sha256(K, sizeof K, auc_challenge, chlen,
                response_out, rlen);
    secure_wipe(K, sizeof K);
    return 0;
}


/* ---- Breakage ---------------------------------------------
 *
 *  AGENCY_KMF_ROOT factored:
 *    - Attacker mints KMF-look-alike certs, pushes forged OTAR
 *      envelopes with attacker-controlled TEKs. From that
 *      moment any traffic encrypted under those TEKs is
 *      recoverable; FBI/CBP/DEA field ops / tactical PD talkgroups
 *      eavesdroppable in real time.
 *
 *  VENDOR_FW_ROOT factored (Motorola/L3Harris/JVCKenwood):
 *    - Signed firmware fleet-wide that disables encryption or
 *      leaks keys off-band. Public-safety comms compromised
 *      during active emergencies — life-safety scenario.
 *
 *  Dispatch console RFSS CA factored (Motorola VIDA, MCC7500):
 *    - Forged dispatch commands inside operational talkgroups:
 *      false officer-down alerts, bogus all-unit calls, bad
 *      mutual-aid during active incidents.
 *
 *  FirstNet / MCPTT identity CA factored:
 *    - Mission-critical push-to-talk integrity compromised
 *      across the US public-safety mobile-broadband system.
 */
