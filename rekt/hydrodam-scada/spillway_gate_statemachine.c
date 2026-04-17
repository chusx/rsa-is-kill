/*
 * spillway_gate_statemachine.c
 *
 * Dam spillway radial-gate hoist control state machine for
 * USACE / Bureau of Reclamation / BC Hydro / EDF hydrology
 * SCADA. Gate raise/lower is a signed operator command;
 * the sequencer enforces an FERC / ICOLD approved ramp
 * profile to avoid downstream surge.
 *
 * Vendors:
 *   - Rockwell ControlLogix with FactoryTalk SE
 *   - Emerson Ovation
 *   - Schneider Modicon + Wonderware System Platform
 *   - ABB 800xA (older plants)
 *
 * Gate decisions propagate through three interlocks:
 *   1. Reservoir-level permissive (from forebay sensors)
 *   2. Downstream flood-advisory gate (from NWS & Corps)
 *   3. Structural permissive (post-seismic sensor block)
 *
 * Any of the three can veto; only a signed "Emergency
 * Spillway Directive" (ESD) under the dam-safety officer's
 * RSA key can override #2 under a precautionary release.
 */

#include <stdint.h>
#include <string.h>
#include "dam.h"

extern const uint8_t DAM_SAFETY_ROOT_PUB[384];
extern const uint8_t RTO_DISPATCH_ROOT_PUB[384];   /* for energy calls */

enum gate_state {
    GS_CLOSED, GS_OPENING, GS_HELD, GS_CLOSING, GS_EMERGENCY,
};

struct gate_cmd {
    char       dam_id[12];
    uint8_t    gate_idx;               /* 1..N radial gates      */
    float      target_ft;              /* gate-top elevation     */
    float      ramp_fps;               /* ft/s ramp rate         */
    uint32_t   cmd_seq;
    uint64_t   issued_utc_ns;
    uint8_t    mode;                   /* NORMAL / ESD           */
    char       operator_id[16];
    char       dso_id[16];             /* dam safety officer     */
    uint8_t    op_cert[2048]; size_t op_cert_len;
    uint8_t    dso_cert[2048]; size_t dso_cert_len;
    uint8_t    op_sig[384];
    uint8_t    dso_sig[384];
};

int spillway_accept(const struct gate_cmd *c,
                    struct gate_ctx *g)
{
    if (c->cmd_seq <= g->last_seq) return GS_ERR_REPLAY;

    if (x509_chain_verify(c->op_cert, c->op_cert_len,
            DAM_SAFETY_ROOT_PUB, sizeof DAM_SAFETY_ROOT_PUB))
        return GS_ERR_OP_CHAIN;

    if (c->mode == MODE_ESD &&
        x509_chain_verify(c->dso_cert, c->dso_cert_len,
            DAM_SAFETY_ROOT_PUB, sizeof DAM_SAFETY_ROOT_PUB))
        return GS_ERR_DSO_CHAIN;

    uint8_t h[32];
    sha256_of(c, offsetof(struct gate_cmd, op_cert), h);
    if (verify_with_cert(c->op_cert, c->op_cert_len,
                         h, c->op_sig, sizeof c->op_sig))
        return GS_ERR_OP_SIG;
    if (c->mode == MODE_ESD &&
        verify_with_cert(c->dso_cert, c->dso_cert_len,
                         h, c->dso_sig, sizeof c->dso_sig))
        return GS_ERR_DSO_SIG;

    /* Interlock chain */
    if (forebay_level_ft() > dam_max_elev(c->dam_id))
        goto allow_open;                /* overtop imminent */
    if (!flood_warning_permissive(c->dam_id) && c->mode != MODE_ESD)
        return GS_ERR_DS_FLOOD;
    if (!seismic_permissive(c->dam_id))
        return GS_ERR_SEISMIC;
    if (c->ramp_fps > FERC_MAX_RAMP)
        return GS_ERR_RAMP;

allow_open:
    g->last_seq = c->cmd_seq;
    return spillway_ramp_to(c->gate_idx, c->target_ft, c->ramp_fps);
}

/* =========================================================
 *  Flood-release coordination: the Corps / BC Hydro / EDF
 *  central office issues a multi-dam signed "Release Order"
 *  that cascades across a river system (Columbia, Rhône,
 *  Peace etc.). The RTO may also issue signed load-shed
 *  curtailments that affect turbine dispatch indirectly.
 * ========================================================= */

struct cascade_release_order {
    char      river_basin[16];
    uint32_t  order_id;
    uint64_t  effective_ns;
    uint8_t   n_dams;
    struct {
        char    dam_id[12];
        float   release_cfs;
        uint32_t duration_s;
    } per_dam[32];
    uint8_t   corps_cert[2048]; size_t corps_cert_len;
    uint8_t   corps_sig[384];
};

/* ---- Consequence of factoring -----------------------------
 *  DAM_SAFETY_ROOT factored:
 *    Coordinated gate-open across a river system during
 *    spring freshet; downstream inundation wipes out
 *    communities. Oroville-2017-class event, deliberately
 *    induced. Loss of life plausible; billions in damage.
 *    Also: forged "close" during PMF (probable maximum
 *    flood) -> dam overtopping and structural failure.
 *  RTO_DISPATCH_ROOT factored:
 *    Sham dispatch of turbine units triggers cascading
 *    generation loss on the bulk-power system; secondary
 *    dam-safety risks if forebay management is disrupted.
 *  Recovery: replace plant PKI + re-certify every RTU; FERC
 *  Part 12D dam-safety review mandated; operating restrictions
 *  (reduced conservation pool) while remediation proceeds.
 * --------------------------------------------------------- */
