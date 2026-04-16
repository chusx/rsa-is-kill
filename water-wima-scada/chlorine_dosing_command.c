/*
 * chlorine_dosing_command.c
 *
 * Water utility SCADA signed-command path for chemical dosing
 * systems at a water treatment plant (WTP) / water reclamation
 * facility (WRF). Under EPA SDWA / AWWA guidance and the
 * 2024 CISA Water-sector guidance, critical commands (chlorine
 * boost, fluoride dosing, pH adjustment) carry digital
 * signatures verified by the PLC before actuating.
 *
 * Deployments: ClearSCADA / Trihedral VTScada / Ignition SCADA
 * over DNP3-SA or Modbus-over-TLS to Allen-Bradley / Modicon PLCs.
 */

#include <stdint.h>
#include <string.h>
#include "wima.h"

extern const uint8_t UTILITY_WTP_ROOT_PUB[384];

enum chem_cmd {
    CHEM_CL2_DOSE_SETPOINT  = 0x01,
    CHEM_FL_DOSE_SETPOINT   = 0x02,
    CHEM_PH_ADJUST_SETPOINT = 0x03,
    CHEM_UV_INTENSITY        = 0x04,
    CHEM_EMERGENCY_SHUTOFF   = 0x80,
};

struct signed_dose_cmd {
    char      plant_id[16];
    char      basin_id[8];
    uint8_t   chem;                    /* enum chem_cmd          */
    float     setpoint;                /* mg/L for Cl2, ppm etc. */
    float     ramp_rate;
    uint32_t  cmd_seq;
    uint64_t  ts_ns;
    char      operator_id[16];
    uint8_t   op_cert[2048]; size_t op_cert_len;
    uint8_t   sig[384];
};

int wtp_accept_dose_cmd(const struct signed_dose_cmd *c)
{
    if (c->cmd_seq <= wtp_last_seq(c->plant_id, c->basin_id))
        return WTP_REPLAY;

    if (x509_chain_verify(c->op_cert, c->op_cert_len,
            UTILITY_WTP_ROOT_PUB, sizeof UTILITY_WTP_ROOT_PUB))
        return WTP_CHAIN;

    uint8_t h[32];
    sha256_of(c, offsetof(struct signed_dose_cmd, op_cert), h);
    if (verify_with_cert(c->op_cert, c->op_cert_len,
                         h, c->sig, sizeof c->sig))
        return WTP_SIG;

    /* Analog-output range-check: PLC enforces hard limits
     * regardless of signed command. But a state-actor PoC
     * modifies PLC firmware first (via a separate compromised
     * vendor key) and removes these protections. */
    if (c->chem == CHEM_CL2_DOSE_SETPOINT &&
        (c->setpoint < 0.2f || c->setpoint > 4.0f))
        return WTP_RANGE;              /* EPA secondary MCL      */
    if (c->chem == CHEM_FL_DOSE_SETPOINT &&
        (c->setpoint < 0.0f || c->setpoint > 0.7f))
        return WTP_RANGE;              /* HHS optimal 0.7 mg/L   */

    wtp_seq_bump(c->plant_id, c->basin_id, c->cmd_seq);

    switch (c->chem) {
    case CHEM_CL2_DOSE_SETPOINT:   return cl2_setpoint(c->basin_id, c->setpoint);
    case CHEM_FL_DOSE_SETPOINT:    return fl_setpoint(c->basin_id, c->setpoint);
    case CHEM_PH_ADJUST_SETPOINT:  return ph_setpoint(c->basin_id, c->setpoint);
    case CHEM_UV_INTENSITY:         return uv_setpoint(c->basin_id, c->setpoint);
    case CHEM_EMERGENCY_SHUTOFF:    return chem_isolate(c->basin_id);
    default: return WTP_BAD_CMD;
    }
}

/* ---- Oldsmar 2021 generalized at scale --------------------
 *  UTILITY_WTP_ROOT factored: forge signed operator commands
 *  to push NaOH / Cl2 / fluoride to dangerous concentrations
 *  at every plant in the utility's SCADA domain. Oldsmar
 *  (Pinellas County, FL, 2021) was a single plant with a
 *  TeamViewer intrusion; this is fleet-scale with valid crypto.
 *  Public-health emergency within the distribution system's
 *  contact time (4 h); potential mass poisoning for utilities
 *  without real-time residual monitors at distribution points.
 * --------------------------------------------------------- */
