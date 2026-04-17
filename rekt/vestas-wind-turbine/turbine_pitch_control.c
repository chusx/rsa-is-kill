/*
 * turbine_pitch_control.c
 *
 * Vestas V150-4.2MW / Siemens Gamesa SG-14-222DD / GE Haliade-X
 * wind turbine SCADA command path for blade pitch, yaw, and
 * emergency feather. The OEM's SCADA CMS (Central Monitoring
 * System) issues signed commands to each turbine's nacelle
 * controller over VPN / DTLS.
 *
 * Blade pitch is the safety-critical actuator: pitching to
 * feather (90°) stops the rotor aerodynamically; pitching to
 * fine (0°) in a gust -> overspeed -> structural failure
 * (Hornsea One class).
 */

#include <stdint.h>
#include <string.h>
#include "wind.h"

extern const uint8_t OEM_TURBINE_ROOT_PUB[384];

struct pitch_cmd {
    char       farm_id[12];           /* "HornseaTwo"            */
    char       turbine_id[8];         /* "T-042"                 */
    uint32_t   cmd_seq;
    uint64_t   ts_ns;
    float      pitch_angle_deg;       /* 0 = fine, 90 = feather  */
    float      ramp_rate_deg_s;
    uint8_t    mode;                  /* NORMAL / EMERGENCY      */
    uint8_t    op_cert[2048]; size_t op_cert_len;
    uint8_t    sig[384];
};

int nacelle_accept_pitch(const struct pitch_cmd *c)
{
    if (c->cmd_seq <= nacelle_last_seq(c->turbine_id))
        return WT_REPLAY;
    if (x509_chain_verify(c->op_cert, c->op_cert_len,
            OEM_TURBINE_ROOT_PUB, sizeof OEM_TURBINE_ROOT_PUB))
        return WT_CHAIN;
    uint8_t h[32];
    sha256_of(c, offsetof(struct pitch_cmd, op_cert), h);
    if (verify_with_cert(c->op_cert, c->op_cert_len,
                         h, c->sig, sizeof c->sig))
        return WT_SIG;

    /* Safety: nacelle controller has hard limits on pitch ramp
     * rate to prevent blade root fatigue; but these limits are
     * in firmware, and firmware is also signed by the same OEM
     * root (see separate FW update path). */
    if (c->pitch_angle_deg < 0.0f || c->pitch_angle_deg > 95.0f)
        return WT_RANGE;
    if (c->ramp_rate_deg_s > 8.0f && c->mode != EMERGENCY)
        return WT_RAMP;

    nacelle_seq_bump(c->turbine_id, c->cmd_seq);
    return blade_pitch_drive(c->pitch_angle_deg, c->ramp_rate_deg_s);
}

/* ---- Grid + structural attack surface ---------------------
 *  OEM_TURBINE_ROOT factored:
 *    - Forge pitch-to-fine (0°) on every turbine in an
 *      offshore wind farm during a storm. Aerodynamic
 *      overspeed -> blade throw / tower collapse.
 *    - Simultaneous feather across a fleet = instant loss
 *      of GW-scale generation. Grid frequency drops;
 *      cascading load-shed. Hornsea One 2019 event (1.1 GW
 *      trip) was caused by a protection mis-config; this
 *      achieves the same at forged-command scale.
 *    - Forge firmware updates (same root) to remove safety
 *      interlocks. Persistent; only a nacelle-by-nacelle
 *      truck-roll restores.
 *  Recovery: OEM rotates OT PKI; every nacelle controller
 *  (thousands per large farm) needs new trust store. Offshore
 *  turbines require CTV or SOV access; weather-window
 *  dependent. Measured in months per farm.
 * --------------------------------------------------------- */
