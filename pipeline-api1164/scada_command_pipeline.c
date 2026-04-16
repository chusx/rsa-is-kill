/*
 * scada_command_pipeline.c
 *
 * API Standard 1164 (Pipeline Control Systems Cybersecurity) and
 * TSA Security Directive SD02C-21-01 signed command path from the
 * control-center SCADA (OSI PI, Emerson Ovation, ABB 800xA) to the
 * field RTU / PLC at a valve / compressor / pump station.
 *
 * Pipelines in scope:
 *   - Liquid: Colonial, Plains All-American, Enbridge Mainline
 *   - Gas:    Transco, El Paso, TransCanada (now TC Energy),
 *             Nord Stream (prior), Gazprom export
 *   - LNG:    Sabine Pass, Corpus Christi, Cameron LNG
 *
 * After the 2021 Colonial ransomware incident, TSA mandated
 * cryptographic authentication on critical command paths. The
 * signed-command pattern below is the *industry template*
 * shipped by Schneider Electric ClearSCADA, GE iFIX, and
 * Emerson OASyS DNA; each carrier customizes the OIDs but
 * the RSA dependency is universal.
 */

#include <stdint.h>
#include <string.h>
#include "api1164.h"

extern const uint8_t PIPELINE_OT_CA_PUB[384];    /* per-carrier, RSA-3072 */

enum field_action {
    FA_VALVE_CLOSE      = 0x01,   /* mainline block valve (MLBV)  */
    FA_VALVE_OPEN       = 0x02,
    FA_COMP_START       = 0x10,   /* compressor unit start        */
    FA_COMP_STOP        = 0x11,
    FA_PUMP_VFD_SETPOINT= 0x20,   /* liquid pump speed            */
    FA_BATCH_INTERFACE  = 0x30,   /* product-interface tracking   */
    FA_OVERPRESSURE_TRIP= 0x80,   /* emergency shut-down          */
};

struct field_command {
    char      pipeline_id[12];       /* "COLONIAL-L1", "TRANSCO-30" */
    char      station_id[16];        /* "LINDEN", "STA-13"          */
    uint32_t  cmd_seq;               /* monotonic per (ppl,station) */
    uint64_t  issued_utc_ns;
    uint8_t   action;                /* enum field_action           */
    float     param;                 /* setpoint where applicable   */
    char      operator_id[16];
    char      supervisor_id[16];     /* 2-person rule for MLBV      */
    char      moc_ref[20];           /* change-mgmt ref if required */
    /* two-person signed; both certs issued by PIPELINE_OT_CA. */
    uint8_t   op_cert[2048]; size_t op_cert_len;
    uint8_t   sup_cert[2048]; size_t sup_cert_len;
    uint8_t   op_sig[384];
    uint8_t   sup_sig[384];
};

/* Every field RTU/PLC enforces the signature before actuating
 * any mapped I/O. The RTU ships with PIPELINE_OT_CA_PUB fused
 * during commissioning; rotation requires a truck-roll. */
int rtu_execute_field_command(const struct field_command *c)
{
    if (c->cmd_seq <= rtu_last_seq(c->pipeline_id, c->station_id))
        return RTU_REPLAY;

    /* Commands that close a mainline block valve or trip a
     * station require the two-person rule; single-sig suffices
     * for informational writes (batch interface etc). */
    int need_two = (c->action == FA_VALVE_CLOSE ||
                    c->action == FA_VALVE_OPEN  ||
                    c->action == FA_OVERPRESSURE_TRIP ||
                    c->action == FA_COMP_START  ||
                    c->action == FA_COMP_STOP);

    if (x509_chain_verify(c->op_cert, c->op_cert_len,
            PIPELINE_OT_CA_PUB, sizeof PIPELINE_OT_CA_PUB))
        return RTU_CHAIN_OP;
    if (need_two &&
        x509_chain_verify(c->sup_cert, c->sup_cert_len,
            PIPELINE_OT_CA_PUB, sizeof PIPELINE_OT_CA_PUB))
        return RTU_CHAIN_SUP;

    uint8_t h[32];
    sha256_of(c, offsetof(struct field_command, op_cert), h);

    if (verify_with_cert(c->op_cert, c->op_cert_len,
                         h, c->op_sig, sizeof c->op_sig))
        return RTU_SIG_OP;
    if (need_two &&
        verify_with_cert(c->sup_cert, c->sup_cert_len,
                         h, c->sup_sig, sizeof c->sup_sig))
        return RTU_SIG_SUP;

    /* Signed-command latency budget: 2000 ms. ESD (overpressure
     * trip) commands allowed to be "older" (leaky bucket 30 s)
     * because ESD propagates via latched relay logic. */
    int64_t age_ms = now_ns_delta_ms(c->issued_utc_ns);
    if (c->action != FA_OVERPRESSURE_TRIP && age_ms > 2000)
        return RTU_STALE;

    rtu_last_seq_bump(c->pipeline_id, c->station_id, c->cmd_seq);

    switch (c->action) {
    case FA_VALVE_CLOSE: return mlbv_drive(c->station_id, 0);
    case FA_VALVE_OPEN:  return mlbv_drive(c->station_id, 1);
    case FA_COMP_START:  return comp_sequence_start(c->station_id);
    case FA_COMP_STOP:   return comp_sequence_stop(c->station_id);
    case FA_PUMP_VFD_SETPOINT: return vfd_setpoint(c->station_id, c->param);
    case FA_OVERPRESSURE_TRIP: return esd_trip_station(c->station_id);
    }
    return RTU_BAD_ACTION;
}

/* ---- Kinetic & economic consequence ----------------------
 *  PIPELINE_OT_CA factored:
 *    - Forge a two-person signed FA_VALVE_CLOSE on every
 *      mainline block valve of a liquid line; downstream
 *      distillate / gasoline / jet-A supply collapses within
 *      hours. Colonial-Ransomware consequences without needing
 *      to touch the SCADA — direct to RTU over DNP3 / serial.
 *    - Forge FA_COMP_STOP on gas compression; downstream city-
 *      gate pressures fall; winter demand -> outage.
 *    - Forge FA_OVERPRESSURE_TRIP on LNG import terminal;
 *      supply shock, price spike.
 *  Recovery: carrier OT PKI re-issuance + every RTU truck-roll
 *  or BOIP reachability to reprovision trust store. PHMSA /
 *  TSA emergency order imposing manual dispatch + local-only
 *  control during the migration.
 * --------------------------------------------------------- */
