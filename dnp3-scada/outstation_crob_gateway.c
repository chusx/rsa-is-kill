/*
 * outstation_crob_gateway.c
 *
 * DNP3 Secure Authentication v5 (IEC 62351-5) outstation-side
 * dispatcher for Control Relay Output Block (CROB, group 12
 * variation 1) and Analog Output Block (AOB) commands.
 *
 * This is the code path that actually drives a relay coil on
 * a distribution recloser, feeder breaker, capacitor-bank
 * switch, substation transformer LTC, or water/wastewater
 * pump — after the SAv5 RSA-anchored update-key exchange
 * has been completed (see dnp3_sav5_rsa_auth.c in this dir).
 *
 * Deployments include:
 *   - SEL RTACs, GE D400, ABB RTU560, Schweitzer SEL-3555
 *   - Water: ClearSCADA / Trihedral VTScada via DNP3
 *   - Rail: wayside Power Distribution Control
 */

#include <stdint.h>
#include <string.h>
#include "dnp3.h"

enum crob_control_code {
    CCC_NUL                = 0x00,
    CCC_PULSE_ON           = 0x01,
    CCC_PULSE_OFF          = 0x02,
    CCC_LATCH_ON           = 0x03,
    CCC_LATCH_OFF          = 0x04,
    CCC_CLOSE              = 0x41,     /* close — trip/close logic */
    CCC_TRIP               = 0x81,
};

/* Group 12 Var 1 object (DNP3 Application Layer). */
struct g12v1_crob {
    uint8_t   control_code;
    uint8_t   count;
    uint32_t  on_time_ms;
    uint32_t  off_time_ms;
    uint8_t   status;                   /* 0 on outgoing          */
};

/* SAv5 authenticated envelope. Every CROB/AOB write is
 * wrapped in an Aggressive Mode or Non-Aggressive Mode
 * authenticated APDU. Session-key MAC chain roots at the
 * RSA-signed Update-Key Authority (UKA) — see dnp3_sav5_rsa_auth.c */
struct sav5_apdu {
    uint16_t  user_number;
    uint32_t  csq;                      /* challenge seq. number  */
    uint8_t   mac_alg;                  /* 3 = HMAC-SHA256        */
    uint8_t   mac[16];                  /* truncated              */
    uint8_t   body[256];
    size_t    body_len;
};

/* Select-Before-Operate: outstation enforces SBO window
 * (commonly 2-10 s) and count match. Any CROB_CLOSE / CROB_TRIP
 * that bypasses SBO is a protocol violation. */
struct sbo_ctx {
    uint16_t  index;                    /* DNP3 point index       */
    uint8_t   control_code;
    uint32_t  selected_ts_ms;
    uint16_t  user_number;
};

static struct sbo_ctx sbo_slot;

int dnp3_handle_g12_select(uint16_t index,
                           const struct g12v1_crob *c,
                           uint16_t user_number)
{
    /* Point-level permission: UKA certificate extension
     * 1.3.6.1.4.1.50000.62351.5.1 carries the per-user
     * bitmap of writable DNP3 point ranges. Non-authorized
     * points return IIN2.4 (NO_AUTH). */
    if (!user_can_write_point(user_number, index))
        return IIN2_4_NO_AUTH;

    sbo_slot.index           = index;
    sbo_slot.control_code    = c->control_code;
    sbo_slot.selected_ts_ms  = ms_since_boot();
    sbo_slot.user_number     = user_number;
    return 0;
}

int dnp3_handle_g12_operate(uint16_t index,
                            const struct g12v1_crob *c,
                            uint16_t user_number)
{
    /* Strict SBO pairing. */
    if (sbo_slot.index != index ||
        sbo_slot.control_code != c->control_code ||
        sbo_slot.user_number != user_number ||
        ms_since_boot() - sbo_slot.selected_ts_ms > 5000)
        return IIN2_4_NO_SBO;

    /* Actually drive the output. On a utility recloser /
     * feeder breaker, CCC_TRIP here opens the breaker
     * immediately; CCC_CLOSE closes. No additional
     * interlock at the DNP3 layer — interlock is the
     * job of the IED's protection logic. */
    switch (c->control_code) {
    case CCC_TRIP:       return relay_drive_trip(index);
    case CCC_CLOSE:      return relay_drive_close(index);
    case CCC_PULSE_ON:   return relay_pulse(index, c->on_time_ms);
    case CCC_LATCH_ON:   return relay_latch(index, 1);
    case CCC_LATCH_OFF:  return relay_latch(index, 0);
    default:             return IIN2_2_OBJ_UNKNOWN;
    }
}

/* Entry from SAv5 layer: only called after the SAv5 MAC has
 * verified against the session key that was delivered under
 * an RSA signature from the Authority Certificate. */
int dnp3_apdu_dispatch(const struct sav5_apdu *a)
{
    /* Walk objects; for each g12v1, call select or operate
     * depending on function code (Select=3, Operate=4,
     * Direct-Operate=5, Direct-Operate-No-Ack=6). */
    uint8_t fc = apdu_function_code(a);
    uint16_t index;
    struct g12v1_crob c;
    while (!apdu_next_g12v1(a, &index, &c)) {
        switch (fc) {
        case 3: dnp3_handle_g12_select(index, &c, a->user_number); break;
        case 4: dnp3_handle_g12_operate(index, &c, a->user_number); break;
        case 5: dnp3_handle_g12_select(index, &c, a->user_number);
                dnp3_handle_g12_operate(index, &c, a->user_number); break;
        }
    }
    return 0;
}

/* ---- Effect of Authority Certificate RSA factoring -----
 *  - Forge UKA-signed Set-Session-Key (g120v6) message;
 *    RTU now trusts attacker-chosen session keys and every
 *    subsequent CROB passes MAC verification.
 *  - Attacker issues CCC_TRIP to every feeder breaker in a
 *    distribution substation — load-shed cascade into
 *    sub-transmission. Ukraine-2015 class event.
 *  - Water: open every valve on a lift station; wastewater
 *    overflow / public-health event.
 *  Recovery: utility must re-commission every RTU's UKA trust
 *  anchor. Many utilities have 10-30k RTUs across a service
 *  territory; truck-roll per site measured in person-years.
 * --------------------------------------------------------- */
