/*
 * scanner_job_and_reticle_chain.c
 *
 * Fab MES-integrated controller: verifies reticle identity,
 * recipe signature, and ASML scanner job manifest before
 * releasing the lot for exposure. Pattern approximates an
 * Applied Materials SmartFactory + ASML TWINSCAN NXE:3800E
 * integration at a logic foundry.
 */

#include <stdint.h>
#include <string.h>
#include "mes.h"
#include "rsa_pss.h"

extern const uint8_t ASML_FW_ROOT_PUB[384];
extern const uint8_t FAB_PI_ROOT_PUB[384];          /* process-integration */
extern const uint8_t CUSTOMER_TAPEOUT_ROOT_PUB[384];/* fabless IP signer */


/* =========================================================
 *  1. Reticle ID ↔ signed mask-data manifest
 * ========================================================= */

struct mask_manifest {
    char      customer_id[16];        /* anonymised: NVDA, AAPL, ... */
    char      design_id[32];          /* e.g. "HopperGH100-M7" */
    char      maskset_hash[32];       /* SHA-256 over OASIS stream */
    uint8_t   n_layers;
    struct {
        uint8_t  reticle_barcode[24]; /* physical ID on pellicle frame */
        uint8_t  layer_hash[32];
    } layers[80];
    uint8_t   customer_cert[1536];
    size_t    cert_len;
    uint8_t   sig[384];               /* fabless customer's tapeout key */
};

int mes_admit_reticle(const struct mask_manifest *mm,
                      const uint8_t *scanned_barcode,
                      uint8_t layer_idx)
{
    if (x509_chain_verify(mm->customer_cert, mm->cert_len,
                          CUSTOMER_TAPEOUT_ROOT_PUB,
                          sizeof CUSTOMER_TAPEOUT_ROOT_PUB) != 0)
        return ERR_CUST_CHAIN;

    uint8_t n[384], e[4];
    size_t n_len, e_len;
    x509_extract_pub(mm->customer_cert, mm->cert_len,
                     n, sizeof n, &n_len, e, sizeof e, &e_len);

    uint8_t h[32];
    sha256_of(mm, offsetof(struct mask_manifest, sig), h);
    if (rsa_pss_verify_sha256(n, n_len, e, e_len, h, 32,
                              mm->sig, sizeof mm->sig) != 0)
        return ERR_MM_SIG;

    if (layer_idx >= mm->n_layers) return ERR_LAYER;
    if (memcmp(mm->layers[layer_idx].reticle_barcode,
               scanned_barcode, 24))
        return ERR_WRONG_RETICLE;
    return 0;
}


/* =========================================================
 *  2. ASML scanner job-file signature verification
 * ========================================================= */

struct scanner_job {
    char      scanner_id[12];         /* "NXE3800E-07" */
    char      recipe_name[32];
    char      design_id[32];
    uint32_t  dose_mJcm2_x100;
    int32_t   focus_offset_nm;
    uint8_t   illumination_mode[16];
    uint8_t   overlay_corrections[256];
    uint8_t   pi_cert[1536];
    size_t    pi_cert_len;
    uint8_t   sig[384];               /* fab PI signing */
};

int scanner_accept_job(const struct scanner_job *j,
                       const struct mask_manifest *mm)
{
    if (strncmp(j->design_id, mm->design_id, 32))
        return ERR_DESIGN_MISMATCH;

    if (x509_chain_verify(j->pi_cert, j->pi_cert_len,
                          FAB_PI_ROOT_PUB,
                          sizeof FAB_PI_ROOT_PUB) != 0)
        return ERR_PI_CHAIN;

    uint8_t n[384], e[4];
    size_t n_len, e_len;
    x509_extract_pub(j->pi_cert, j->pi_cert_len,
                     n, sizeof n, &n_len, e, sizeof e, &e_len);

    uint8_t h[32];
    sha256_of(j, offsetof(struct scanner_job, sig), h);
    if (rsa_pss_verify_sha256(n, n_len, e, e_len, h, 32,
                              j->sig, sizeof j->sig) != 0)
        return ERR_JOB_SIG;

    /* Envelope sanity: process-window bounds */
    if (j->dose_mJcm2_x100 > MAX_DOSE_X100)  return ERR_ENV_DOSE;
    if (abs(j->focus_offset_nm) > 120)       return ERR_ENV_FOCUS;
    return 0;
}


/* =========================================================
 *  3. ASML vendor firmware self-verify (scanner boot)
 * ========================================================= */

struct scanner_fw_manifest {
    char      product[16];
    char      build[32];
    uint32_t  rollback_idx;
    uint8_t   images_sha256[16][32];  /* multi-image: DPU, reticle-stage,
                                       * wafer-stage, source, metrology */
    uint8_t   sig[384];
};

int scanner_fw_self_verify(void)
{
    struct scanner_fw_manifest *m = flash_read_manifest();
    if (m->rollback_idx < tpm_rollback()) return ERR_ROLLBACK;

    for (int i = 0; i < 16; i++) {
        uint8_t h[32];
        sha256_partition(i, h);
        if (memcmp(h, m->images_sha256[i], 32)) return ERR_IMG;
    }

    uint8_t h[32];
    sha256_of(m, offsetof(struct scanner_fw_manifest, sig), h);
    return rsa_pss_verify_sha256(
        ASML_FW_ROOT_PUB, sizeof ASML_FW_ROOT_PUB,
        (uint8_t[]){0x01,0x00,0x01}, 3,
        h, 32, m->sig, sizeof m->sig);
}


/* =========================================================
 *  4. Reticle-library hand-off event signing
 * ========================================================= */

struct reticle_handoff {
    uint8_t   reticle_barcode[24];
    char      from_station[16];       /* inspection, clean, stocker */
    char      to_station[16];
    uint32_t  ts;
    uint8_t   operator_id[16];
    uint8_t   sig[256];
};

int mes_log_handoff(struct reticle_handoff *h)
{
    h->ts = now_utc();
    uint8_t digest[32];
    sha256_of(h, offsetof(struct reticle_handoff, sig), digest);
    return rsa_pss_sign_sha256_hsm(
        MES_SIGNING_KEY, digest, 32, h->sig, sizeof h->sig);
}


/* ---- Breakage ---------------------------------------------
 *
 *  ASML FW root factored:
 *    - Malicious firmware silently installed across EUV fleet.
 *      Whole-industry semiconductor disruption.
 *
 *  Fab PI recipe root factored:
 *    - Targeted yield sabotage: dose/focus drift not detected
 *      until end-of-line parametric — days of wafer scrap at
 *      $1M+/hour fab opportunity cost.
 *
 *  Customer tapeout root factored:
 *    - Forged mask manifests — counterfeit chips with valid-
 *      looking provenance; IP-owner liability & supply-chain
 *      confidence destroyed.
 *
 *  MES handoff signing root factored:
 *    - Reticle-B labelled as Reticle-A: cross-customer IP
 *      leakage + mis-exposure; logic-foundry NDA breach at
 *      industrial scale.
 */
