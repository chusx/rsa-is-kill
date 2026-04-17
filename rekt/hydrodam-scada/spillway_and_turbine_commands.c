/*
 * spillway_and_turbine_commands.c
 *
 * Hydro plant RTU/PLC boundary layer between corporate SCADA /
 * ISO AGC and field actuators (spillway gate hydraulics, wicket-
 * gate servos, penstock valves). Enforces signed-command entry
 * and signed-telemetry exit. Pattern approximates an ABB Symphony
 * Plus + GE Mark VIe hydro installation.
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include "hydro.h"
#include "rsa_pss.h"

extern const uint8_t UTILITY_OPS_ROOT_PUB[384];
extern const uint8_t ISO_AGC_ROOT_PUB[384];           /* CAISO/MISO/PJM/ENTSO-E */
extern const uint8_t USACE_WCM_ROOT_PUB[384];         /* water-control manual */


/* =========================================================
 *  1. Spillway-gate command — dual operator signatures
 * ========================================================= */

enum gate_op { OP_SET_OPENING_PCT = 1, OP_EMERG_OPEN = 2, OP_FULL_CLOSE = 3 };

struct spillway_cmd {
    char      plant_id[16];           /* FERC project number */
    uint32_t  gate_id;
    uint32_t  cmd_seq;
    uint32_t  issued_ts;
    uint8_t   op;                     /* enum gate_op */
    float     target_opening_pct;
    float     ramp_pct_per_min;
    char      reason_code[16];        /* "FLOOD", "MAINT", "FISH" */
    uint8_t   op1_cert[1024]; size_t op1_cert_len;
    uint8_t   op2_cert[1024]; size_t op2_cert_len;
    uint8_t   op1_sig[384];
    uint8_t   op2_sig[384];
};

int hydro_execute_spillway_cmd(const struct spillway_cmd *c)
{
    if (c->cmd_seq <= last_spillway_seq(c->gate_id)) return ERR_REPLAY;

    if (x509_chain_verify(c->op1_cert, c->op1_cert_len,
                          UTILITY_OPS_ROOT_PUB,
                          sizeof UTILITY_OPS_ROOT_PUB) ||
        x509_chain_verify(c->op2_cert, c->op2_cert_len,
                          UTILITY_OPS_ROOT_PUB,
                          sizeof UTILITY_OPS_ROOT_PUB))
        return ERR_CHAIN;

    if (same_subject(c->op1_cert, c->op1_cert_len,
                     c->op2_cert, c->op2_cert_len))
        return ERR_SELF_COSIGN;

    uint8_t h[32];
    sha256_of(c, offsetof(struct spillway_cmd, op1_sig), h);

    if (verify_with_cert(c->op1_cert, c->op1_cert_len,
                         h, c->op1_sig, sizeof c->op1_sig) ||
        verify_with_cert(c->op2_cert, c->op2_cert_len,
                         h, c->op2_sig, sizeof c->op2_sig))
        return ERR_SIG;

    /* WCM envelope: during flood season, total outflow rate caps */
    if (!wcm_envelope_ok(c->gate_id, c->target_opening_pct,
                         c->reason_code))
        return ERR_WCM;

    spillway_actuate(c->gate_id, c->target_opening_pct,
                     c->ramp_pct_per_min);
    record_spillway_cmd(c);          /* FERC Part 12 retention */
    return 0;
}


/* =========================================================
 *  2. ISO AGC-signed dispatch to turbine
 * ========================================================= */

struct agc_dispatch {
    char      unit_id[16];            /* "G1", "G2", ... */
    uint32_t  window_start_ts;
    uint32_t  window_end_ts;
    float     mw_setpoint;
    float     ramp_mw_per_min;
    uint8_t   iso_sig[384];
};

int hydro_accept_agc(const struct agc_dispatch *d)
{
    uint8_t h[32];
    sha256_of(d, offsetof(struct agc_dispatch, iso_sig), h);
    if (rsa_pss_verify_sha256(ISO_AGC_ROOT_PUB,
                              sizeof ISO_AGC_ROOT_PUB,
                              (uint8_t[]){0x01,0x00,0x01}, 3,
                              h, 32, d->iso_sig,
                              sizeof d->iso_sig) != 0)
        return ERR_ISO_SIG;

    if (d->mw_setpoint < 0 || d->mw_setpoint > unit_mw_cap(d->unit_id))
        return ERR_ENV;

    governor_schedule(d->unit_id, d->mw_setpoint, d->ramp_mw_per_min);
    return 0;
}


/* =========================================================
 *  3. USACE Water-Control Manual daily guidance
 * ========================================================= */

struct wcm_guidance {
    char      district[12];           /* "NWP", "NWS", "SPK", ... */
    char      project_id[16];
    uint32_t  date;                   /* YYYYMMDD */
    float     min_outflow_cfs;
    float     max_outflow_cfs;
    float     target_forebay_ft;
    uint8_t   sig[384];
};

int hydro_ingest_wcm(const struct wcm_guidance *g)
{
    uint8_t h[32];
    sha256_of(g, offsetof(struct wcm_guidance, sig), h);
    if (rsa_pss_verify_sha256(USACE_WCM_ROOT_PUB,
                              sizeof USACE_WCM_ROOT_PUB,
                              (uint8_t[]){0x01,0x00,0x01}, 3,
                              h, 32, g->sig, sizeof g->sig) != 0)
        return ERR_WCM_SIG;
    wcm_activate(g);
    return 0;
}


/* =========================================================
 *  4. Signed dam-safety telemetry emission (piezometers etc)
 * ========================================================= */

struct dam_safety_tel {
    char      project_id[16];
    uint32_t  ts;
    uint16_t  n_channels;
    struct { char tag[12]; float value; } ch[256];
    uint8_t   sig[384];
};

int hydro_emit_safety_telemetry(struct dam_safety_tel *t)
{
    t->ts = (uint32_t)time(NULL);
    uint8_t h[32];
    sha256_of(t, offsetof(struct dam_safety_tel, sig), h);
    return rsa_pss_sign_sha256_hsm(
        DAM_SAFETY_KEY, h, 32, t->sig, sizeof t->sig);
}


/* ---- Breakage ---------------------------------------------
 *
 *  Utility ops dual-signer root factored:
 *    - Spillway misoperation with valid paper trail. Downstream
 *      flooding or upstream overtop. Oroville-class incident
 *      attribution becomes contestable.
 *
 *  ISO AGC root factored:
 *    - Rogue dispatch drives unit to runaway; turbine destroyed.
 *      Grid-level market settlement integrity collapses.
 *
 *  USACE WCM root factored:
 *    - Wrong flood-prep posture — under-release before peak
 *      inflow. Deliberate exacerbation of a flood event.
 *
 *  Dam-safety telemetry key factored:
 *    - Structural-health concealment. FEMA / FERC Part 12
 *      inspection regime defeated.
 */
