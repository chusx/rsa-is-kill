/*
 * sis_moc_and_trip_logic.c
 *
 * SIL-3 Safety Instrumented System logic solver (SIF runtime):
 * app-program loader, MoC-signed setpoint change handler, proof-
 * test result signer, bypass authorisation gate. Pattern approx.
 * Triconex/Tricon + HIMA HIMax + Siemens S7-400FH.
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include "sis.h"
#include "rsa_pss.h"

extern const uint8_t VENDOR_SIS_FW_ROOT_PUB[384];
extern const uint8_t FSA_TUV_ROOT_PUB[384];         /* TÜV / exida */
extern const uint8_t SITE_MOC_ROOT_PUB[384];        /* end-user PSE */


/* =========================================================
 *  1. Application-program load with vendor + FSA co-sign
 * ========================================================= */

struct sif_app_program {
    char      site_id[16];            /* "REF-BTX-01" */
    char      sif_tag[24];            /* "SIF-100-HP-TRIP" */
    uint8_t   sil_target;             /* 1..4 */
    uint32_t  n_inputs, n_outputs;
    uint8_t   logic_bytecode[16384];
    uint32_t  bytecode_len;
    uint8_t   vendor_sig[384];
    uint8_t   fsa_sig[384];           /* independent TÜV assessor */
};

int sis_load_sif(const struct sif_app_program *p)
{
    uint8_t h[32];
    sha256_of(p, offsetof(struct sif_app_program, vendor_sig), h);

    if (rsa_pss_verify_sha256(VENDOR_SIS_FW_ROOT_PUB,
                              sizeof VENDOR_SIS_FW_ROOT_PUB,
                              (uint8_t[]){0x01,0x00,0x01}, 3,
                              h, 32, p->vendor_sig,
                              sizeof p->vendor_sig) != 0)
        return ERR_VENDOR;

    if (rsa_pss_verify_sha256(FSA_TUV_ROOT_PUB,
                              sizeof FSA_TUV_ROOT_PUB,
                              (uint8_t[]){0x01,0x00,0x01}, 3,
                              h, 32, p->fsa_sig,
                              sizeof p->fsa_sig) != 0)
        return ERR_FSA;

    return logic_solver_activate(p);
}


/* =========================================================
 *  2. MoC setpoint change — two-person signed workflow
 * ========================================================= */

struct moc_setpoint_change {
    char      sif_tag[24];
    char      param[16];              /* "HI_PRESS_TRIP" */
    double    old_value, new_value;
    char      justification[256];
    char      author_npi[12];         /* process-safety engineer */
    char      reviewer_npi[12];       /* independent reviewer */
    uint32_t  effective_ts;
    uint8_t   author_cert[1024];
    size_t    author_cert_len;
    uint8_t   reviewer_cert[1024];
    size_t    reviewer_cert_len;
    uint8_t   author_sig[384];
    uint8_t   reviewer_sig[384];
};

int sis_apply_moc(const struct moc_setpoint_change *m)
{
    if (!strcmp(m->author_npi, m->reviewer_npi))
        return ERR_SELF_REVIEW;

    /* Both identities chain to site MoC root */
    if (x509_chain_verify(m->author_cert, m->author_cert_len,
                          SITE_MOC_ROOT_PUB,
                          sizeof SITE_MOC_ROOT_PUB) ||
        x509_chain_verify(m->reviewer_cert, m->reviewer_cert_len,
                          SITE_MOC_ROOT_PUB,
                          sizeof SITE_MOC_ROOT_PUB))
        return ERR_CHAIN;

    uint8_t h[32];
    sha256_of(m, offsetof(struct moc_setpoint_change, author_sig), h);

    if (verify_with_leaf(m->author_cert, m->author_cert_len,
                         h, m->author_sig, sizeof m->author_sig) != 0)
        return ERR_AUTHOR_SIG;
    if (verify_with_leaf(m->reviewer_cert, m->reviewer_cert_len,
                         h, m->reviewer_sig, sizeof m->reviewer_sig) != 0)
        return ERR_REVIEW_SIG;

    /* Envelope: setpoint may not leave SIL-justified band */
    if (!setpoint_within_sil_band(m->sif_tag, m->param, m->new_value))
        return ERR_OUTSIDE_SIL_BAND;

    apply_setpoint(m->sif_tag, m->param, m->new_value);
    engineering_history_append(m, sizeof *m);   /* audit trail */
    return 0;
}


/* =========================================================
 *  3. Proof-test result signing
 * ========================================================= */

struct proof_test_result {
    char      sif_tag[24];
    uint32_t  test_ts;
    uint32_t  prev_test_ts;
    uint8_t   pass_fail;              /* 1=pass */
    double    response_time_ms;
    char      technician_id[12];
    uint8_t   sig[384];
};

int sis_sign_proof_test(struct proof_test_result *pt)
{
    pt->test_ts = (uint32_t)time(NULL);
    uint8_t h[32];
    sha256_of(pt, offsetof(struct proof_test_result, sig), h);
    return rsa_pss_sign_sha256_hsm(
        SIS_PROOF_TEST_KEY, h, 32, pt->sig, sizeof pt->sig);
}


/* =========================================================
 *  4. Bypass authorisation with time-limit
 * ========================================================= */

struct bypass_auth {
    char      sif_tag[24];
    uint32_t  start_ts;
    uint32_t  expire_ts;              /* SIS enforces auto-unbypass */
    char      reason[128];
    char      authoriser_npi[12];
    uint8_t   sig[384];
};

int sis_accept_bypass(const struct bypass_auth *b)
{
    if (b->expire_ts - b->start_ts > MAX_BYPASS_DURATION_S)
        return ERR_TOO_LONG;

    uint8_t h[32];
    sha256_of(b, offsetof(struct bypass_auth, sig), h);
    if (rsa_pss_verify_sha256(SITE_MOC_ROOT_PUB,
                              sizeof SITE_MOC_ROOT_PUB,
                              (uint8_t[]){0x01,0x00,0x01}, 3,
                              h, 32, b->sig, sizeof b->sig) != 0)
        return ERR_SIG;

    schedule_auto_unbypass(b->sif_tag, b->expire_ts);
    bypass_apply(b->sif_tag);
    return 0;
}


/* ---- Breakage ---------------------------------------------
 *
 *  Vendor SIS firmware root factored:
 *    - Installed-base-scale Triton-class attack; trip functions
 *      silently disabled while reporting healthy.
 *
 *  FSA (TÜV/exida) root factored:
 *    - Application logic's SIL attestation untrustworthy;
 *      plants forced offline for independent reverification.
 *
 *  Site MoC root factored:
 *    - Forged setpoint changes slide trip thresholds outside
 *      the safe envelope — eventual process-safety event with
 *      a legit-looking MoC paper trail.
 *
 *  Bypass authorisation root factored:
 *    - Bypasses extended silently; protective layer erodes.
 */
