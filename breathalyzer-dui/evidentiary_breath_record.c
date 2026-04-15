/*
 * evidentiary_breath_record.c
 *
 * Evidential breath-alcohol instrument (e.g. Dräger Alcotest 9510,
 * CMI Intoxilyzer 9000). Signed subject-test record, signed
 * calibration check, signed firmware self-verify. Output is
 * courtroom evidence in DUI prosecutions.
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include "instrument.h"
#include "rsa_pss.h"

extern const uint8_t VENDOR_FW_ROOT_PUB[384];
extern const uint8_t AGENCY_OPERATOR_ROOT_PUB[384];


/* =========================================================
 *  1. Firmware self-verify — admissibility anchor
 * ========================================================= */

struct bac_fw_manifest {
    char      product[20];            /* "Alcotest 9510" etc */
    char      build[32];              /* state CPL references this */
    uint32_t  rollback_idx;
    uint8_t   ir_algo_sha256[32];
    uint8_t   fuel_cell_algo_sha256[32];
    uint8_t   integration_sha256[32];
    uint8_t   sig[384];
};

int instrument_fw_self_verify(void)
{
    struct bac_fw_manifest *m = flash_read_manifest();
    if (m->rollback_idx < secure_rollback()) return ERR_ROLLBACK;

    uint8_t h[32];
    sha256_partition(PART_IR,      h); if (memcmp(h, m->ir_algo_sha256, 32))       return ERR_IR;
    sha256_partition(PART_FC,      h); if (memcmp(h, m->fuel_cell_algo_sha256, 32)) return ERR_FC;
    sha256_partition(PART_INT,     h); if (memcmp(h, m->integration_sha256, 32))    return ERR_INT;

    sha256_of(m, offsetof(struct bac_fw_manifest, sig), h);
    return rsa_pss_verify_sha256(
        VENDOR_FW_ROOT_PUB, sizeof VENDOR_FW_ROOT_PUB,
        (uint8_t[]){0x01,0x00,0x01}, 3,
        h, 32, m->sig, sizeof m->sig);
}


/* =========================================================
 *  2. Subject breath-test record
 *
 *  Two separated breath samples (typically 2-10 min apart) with
 *  IR + fuel-cell dual-sensor readings. Accepted only when the
 *  two readings agree within the jurisdictional tolerance
 *  (NHTSA: 0.02 g/210L; many states tighter).
 * ========================================================= */

struct breath_sample {
    uint32_t  ts;
    float     ir_bac_g_per_210L;
    float     fc_bac_g_per_210L;
    float     breath_volume_l;
    float     blow_duration_s;
    float     ambient_temp_c;
    float     humidity_pct;
};

struct subject_record {
    char      agency_id[16];
    char      instrument_serial[16];
    char      officer_id[12];
    char      subject_ref[24];        /* case ID, not PII */
    uint32_t  incident_ts;
    struct breath_sample s1, s2;
    float     reported_bac;           /* lower of the two, per rule */
    uint8_t   mouth_alcohol_flag;     /* slope-detector result */
    uint8_t   rfi_flag;
    uint8_t   officer_cert[1024];
    size_t    officer_cert_len;
    uint8_t   officer_sig[384];       /* officer-credentialed sig */
    uint8_t   instrument_sig[384];    /* instrument HSM sig */
};

int instrument_sign_subject_record(struct subject_record *r,
                                   const uint8_t *officer_sig,
                                   size_t officer_sig_len)
{
    /* Pre-checks: agreement between the two samples (0.02 default),
     * mouth-alcohol slope clear, RFI clear. */
    if (fabsf(r->s1.ir_bac_g_per_210L - r->s2.ir_bac_g_per_210L)
        > AGREEMENT_TOL)                     return ERR_DISAGREE;
    if (r->mouth_alcohol_flag)               return ERR_MOUTH_ALCOHOL;
    if (r->rfi_flag)                         return ERR_RFI;

    /* Officer identity already bound its signature upstream */
    memcpy(r->officer_sig, officer_sig,
           officer_sig_len <= sizeof r->officer_sig ?
           officer_sig_len : sizeof r->officer_sig);

    uint8_t h[32];
    sha256_of(r, offsetof(struct subject_record, instrument_sig), h);
    return rsa_pss_sign_sha256_hsm(
        INSTRUMENT_SIGNING_KEY, h, 32,
        r->instrument_sig, sizeof r->instrument_sig);
}


/* =========================================================
 *  3. Calibration check signing
 * ========================================================= */

struct calibration_check {
    char      instrument_serial[16];
    uint32_t  ts;
    char      simulator_solution_lot[24];
    float     expected_bac;
    float     observed_bac;
    char      technician_id[12];
    uint8_t   sig[384];
};

int instrument_sign_cal_check(struct calibration_check *c)
{
    c->ts = (uint32_t)time(NULL);
    uint8_t h[32];
    sha256_of(c, offsetof(struct calibration_check, sig), h);
    return rsa_pss_sign_sha256_hsm(
        INSTRUMENT_SIGNING_KEY, h, 32, c->sig, sizeof c->sig);
}


/* =========================================================
 *  4. Officer-credentialed co-signature ingestion
 * ========================================================= */

int verify_officer_signature(const uint8_t *cert, size_t cert_len,
                             const uint8_t *body, size_t body_len,
                             const uint8_t *sig, size_t sig_len)
{
    if (x509_chain_verify(cert, cert_len,
                          AGENCY_OPERATOR_ROOT_PUB,
                          sizeof AGENCY_OPERATOR_ROOT_PUB) != 0)
        return ERR_OFF_CHAIN;

    uint8_t n[384], e[4];
    size_t n_len, e_len;
    x509_extract_pub(cert, cert_len, n, sizeof n, &n_len,
                     e, sizeof e, &e_len);

    uint8_t h[32];
    sha256_mem(body, body_len, h);
    return rsa_pss_verify_sha256(n, n_len, e, e_len,
                                 h, 32, sig, sig_len);
}


/* ---- Breakage ---------------------------------------------
 *
 *  Vendor FW root factored:
 *    - Frye/Daubert admissibility collapses for every record
 *      signed by every instrument of that make. Mass DUI
 *      convictions vacated; civil suits against agencies who
 *      cited the instrument.
 *
 *  Instrument per-unit HSM key factored:
 *    - Attacker synthesises exculpatory OR inculpatory
 *      subject records indistinguishable from genuine.
 *
 *  Agency operator root factored:
 *    - Forged officer identities sign records into case files.
 *      Prosecution discovery obligations triggered on every
 *      open case.
 *
 *  Calibration root factored:
 *    - Instrument calibration history unverifiable. Defence
 *      routinely subpoenas and challenges.
 */
