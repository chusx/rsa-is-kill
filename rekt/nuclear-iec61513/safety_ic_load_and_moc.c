/*
 * safety_ic_load_and_moc.c
 *
 * Class-1E safety-I&C processor boundary. Pattern models a
 * Framatome TELEPERM XS function-processor + AC160 application-
 * processor pair (used in EPR + many VVER + Olkiluoto-3 / HPC).
 * Enforces: vendor-signed FW + application load, utility two-
 * person MoC on parameter changes, signed surveillance-test
 * completion records.
 *
 * Real TXS uses a diverse / hard-wired crypto stack; the RSA-
 * signed paths here reflect the administrative + downloadable-
 * parameter trust fabric, not the cycle-critical trip logic
 * itself.
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include "txs.h"
#include "rsa_pss.h"

extern const uint8_t VENDOR_SAFETY_IC_ROOT_PUB[384];
extern const uint8_t UTILITY_ENG_ROOT_PUB[384];
extern const uint8_t NRC_QUAL_ROOT_PUB[384];


/* =========================================================
 *  1. Safety-I&C application load (e.g. RPS logic)
 * ========================================================= */

struct safety_app {
    char      plant_id[16];           /* "BRAIDWOOD-1", "OL3", ... */
    char      system_id[12];          /* "RPS-A", "ESFAS-B", ... */
    char      version[16];
    uint8_t   app_image[524288];      /* SIL-eq logic, 512 KB */
    uint32_t  image_len;
    uint8_t   qual_report_hash[32];   /* NRC SER / ASN EDF reference */
    uint8_t   vendor_sig[384];
    uint8_t   regulator_countersig[384];  /* NRC/ASN on qual attestation */
};

int safety_load_app(const struct safety_app *a)
{
    uint8_t h[32];
    sha256_of(a, offsetof(struct safety_app, vendor_sig), h);

    if (rsa_pss_verify_sha256(VENDOR_SAFETY_IC_ROOT_PUB,
                              sizeof VENDOR_SAFETY_IC_ROOT_PUB,
                              (uint8_t[]){0x01,0x00,0x01}, 3,
                              h, 32, a->vendor_sig,
                              sizeof a->vendor_sig) != 0)
        return ERR_VENDOR;

    if (rsa_pss_verify_sha256(NRC_QUAL_ROOT_PUB,
                              sizeof NRC_QUAL_ROOT_PUB,
                              (uint8_t[]){0x01,0x00,0x01}, 3,
                              h, 32, a->regulator_countersig,
                              sizeof a->regulator_countersig) != 0)
        return ERR_REGULATOR;

    return diverse_backup_gate_then_activate(a);
}


/* =========================================================
 *  2. Two-person MoC parameter change — tech-spec touching
 * ========================================================= */

struct nuc_moc {
    char      plant_id[16];
    char      tech_spec_ref[24];      /* e.g. "TS 3.3.1 RPS INST" */
    char      param[24];              /* "REACTOR-TRIP-NHF-SP" */
    double    old_value, new_value;
    char      usq_determination[256]; /* 10 CFR 50.59 eval summary */
    char      eng_author_id[12];
    char      eng_reviewer_id[12];
    char      shift_manager_id[12];   /* SRO */
    uint8_t   author_sig[384];
    uint8_t   reviewer_sig[384];
    uint8_t   sro_sig[384];
};

int safety_apply_moc(const struct nuc_moc *m)
{
    if (!strcmp(m->eng_author_id, m->eng_reviewer_id))
        return ERR_SELF_REVIEW;

    uint8_t h[32];
    sha256_of(m, offsetof(struct nuc_moc, author_sig), h);

    if (rsa_pss_verify_sha256(UTILITY_ENG_ROOT_PUB,
                              sizeof UTILITY_ENG_ROOT_PUB,
                              (uint8_t[]){0x01,0x00,0x01}, 3,
                              h, 32, m->author_sig,
                              sizeof m->author_sig) != 0)
        return ERR_AUTHOR;
    if (rsa_pss_verify_sha256(UTILITY_ENG_ROOT_PUB,
                              sizeof UTILITY_ENG_ROOT_PUB,
                              (uint8_t[]){0x01,0x00,0x01}, 3,
                              h, 32, m->reviewer_sig,
                              sizeof m->reviewer_sig) != 0)
        return ERR_REVIEWER;
    if (rsa_pss_verify_sha256(UTILITY_ENG_ROOT_PUB,
                              sizeof UTILITY_ENG_ROOT_PUB,
                              (uint8_t[]){0x01,0x00,0x01}, 3,
                              h, 32, m->sro_sig,
                              sizeof m->sro_sig) != 0)
        return ERR_SRO;

    /* Tech-spec bounds: setpoints may not exceed analytical
     * limits minus uncertainty allowance. Second line of
     * defence against forged MoC sliding RPS setpoints. */
    if (!tech_spec_envelope_ok(m->tech_spec_ref, m->param, m->new_value))
        return ERR_TECH_SPEC_ENV;

    apply_safety_param(m->tech_spec_ref, m->param, m->new_value);
    qa_record_append(m);
    return 0;
}


/* =========================================================
 *  3. Surveillance-test completion signing
 * ========================================================= */

struct surveillance_record {
    char      plant_id[16];
    char      surv_id[24];            /* "STP-0-3.3.1-RPS-CH-CALIBRATE" */
    uint32_t  performed_ts;
    uint32_t  due_ts;                 /* Tech-Spec surveillance interval */
    uint8_t   pass_fail;
    char      as_found[128];
    char      as_left[128];
    char      technician_id[12];
    char      sta_id[12];
    uint8_t   tech_sig[384];
    uint8_t   sta_sig[384];           /* Shift Technical Advisor */
};

int safety_sign_surveillance(struct surveillance_record *s,
                             const uint8_t *tech_sig_in,
                             const uint8_t *sta_sig_in)
{
    s->performed_ts = (uint32_t)time(NULL);
    memcpy(s->tech_sig, tech_sig_in, sizeof s->tech_sig);
    memcpy(s->sta_sig,  sta_sig_in,  sizeof s->sta_sig);
    return qa_record_append(s) ? 0 : ERR_STORE;
}


/* =========================================================
 *  4. Fuel-handling / core-map attestation
 * ========================================================= */

struct fuel_load_step {
    char      outage_id[16];
    uint32_t  step_no;
    char      fuel_assembly_id[16];
    uint16_t  from_location;          /* spent-fuel pool coord */
    uint16_t  to_location;            /* core coord */
    char      operator_id[12];
    char      reactor_eng_id[12];
    uint8_t   operator_sig[384];
    uint8_t   reactor_eng_sig[384];
};

int safety_commit_fuel_step(const struct fuel_load_step *f)
{
    uint8_t h[32];
    sha256_of(f, offsetof(struct fuel_load_step, operator_sig), h);
    if (rsa_pss_verify_sha256(UTILITY_ENG_ROOT_PUB,
                              sizeof UTILITY_ENG_ROOT_PUB,
                              (uint8_t[]){0x01,0x00,0x01}, 3,
                              h, 32, f->operator_sig,
                              sizeof f->operator_sig) != 0 ||
        rsa_pss_verify_sha256(UTILITY_ENG_ROOT_PUB,
                              sizeof UTILITY_ENG_ROOT_PUB,
                              (uint8_t[]){0x01,0x00,0x01}, 3,
                              h, 32, f->reactor_eng_sig,
                              sizeof f->reactor_eng_sig) != 0)
        return ERR_SIG;

    if (!core_map_allows(f)) return ERR_CORE_MAP;
    record_fuel_move(f);
    return 0;
}


/* ---- Breakage ---------------------------------------------
 *
 *  Vendor safety-I&C root factored:
 *    - RPS / ESFAS application-loads forgeable across installed
 *      base — catastrophic multi-country nuclear-safety
 *      regulatory crisis. Regulators force fleet shutdown
 *      pending independent reverification.
 *
 *  Utility engineering root factored:
 *    - Forged MoCs slide RPS trip setpoints (mitigated by
 *      tech-spec envelope but still a safety-margin erosion);
 *      forged core-load steps violate criticality safety.
 *
 *  NRC / ASN qualification-attestation root factored:
 *    - Every plant's regulatory qualification file
 *      authenticity lost — forced operational restrictions
 *      until manual re-attestation completes.
 *
 *  Surveillance-record signing factored:
 *    - Tech-spec LCO compliance evidentiary chain collapses;
 *      previously-closed LERs reopen under regulator scrutiny.
 */
