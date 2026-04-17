/*
 * fts_arm_command.c
 *
 * Autonomous Flight Termination System (AFTS) signed command
 * channel for launch vehicles. Under 14 CFR 417 / FAA AC 417-01,
 * every launch vehicle must carry an FTS capable of destroying
 * the vehicle if it leaves the flight corridor. SpaceX Falcon 9 /
 * Heavy and Starship use an AFTS (vs. legacy ground-commanded
 * destruct) that receives signed commands from the Range Safety
 * Officer (RSO) at CCSFS / VSFB / Boca Chica.
 *
 * The AFTS flight computer holds an RSA-3072 verification key;
 * the ground transmitter holds the signing key. Commands include
 * ARM, SAFE, and TERMINATE. The TERMINATE command fires the
 * FTS ordnance to destroy the vehicle.
 */

#include <stdint.h>
#include <string.h>
#include "fts.h"

extern const uint8_t RANGE_RSO_PUB[384];       /* RSA-3072       */

enum fts_cmd {
    FTS_SAFE       = 0x01,
    FTS_ARM        = 0x02,
    FTS_TERMINATE  = 0x03,
    FTS_STATUS_REQ = 0x04,
};

struct fts_command {
    uint8_t   cmd;
    uint32_t  seq;                     /* monotonic              */
    uint8_t   vehicle_id[8];           /* "F9-B1078", "SH-S31"  */
    uint64_t  mission_utc_ns;
    uint8_t   rso_cert[2048]; size_t rso_cert_len;
    uint8_t   sig[384];
};

/* On-board AFTS processor: radiation-hardened, single purpose,
 * physically isolated from avionics GNC. The only I/O is the
 * UHF uplink receiver and the ordnance firing circuit. */
int afts_process_command(const struct fts_command *c)
{
    if (c->seq <= afts_last_seq()) return FTS_REPLAY;
    if (memcmp(c->vehicle_id, afts_vehicle_id(), 8))
        return FTS_WRONG_VEHICLE;

    /* Chain RSO cert to the Range Safety signing root. */
    if (x509_chain_verify(c->rso_cert, c->rso_cert_len,
            RANGE_RSO_PUB, sizeof RANGE_RSO_PUB))
        return FTS_CHAIN;

    uint8_t h[32];
    sha256_of(c, offsetof(struct fts_command, rso_cert), h);
    if (verify_with_cert(c->rso_cert, c->rso_cert_len,
                         h, c->sig, sizeof c->sig))
        return FTS_SIG;

    afts_seq_bump(c->seq);

    switch (c->cmd) {
    case FTS_SAFE:
        afts_state_set(STATE_SAFE);
        return 0;
    case FTS_ARM:
        afts_state_set(STATE_ARMED);
        return 0;
    case FTS_TERMINATE:
        if (afts_state() != STATE_ARMED) return FTS_NOT_ARMED;
        /* Fire ordnance. Irreversible. Vehicle destruction. */
        afts_fire_ordnance();
        return 0;
    case FTS_STATUS_REQ:
        afts_beacon_status();
        return 0;
    }
    return FTS_BAD_CMD;
}

/* ---- Kinetic consequence once RANGE_RSO_PUB factored ------
 *  - Forge FTS_TERMINATE: destroy a launch vehicle in flight,
 *    including crewed missions (Crew Dragon). The RSO channel
 *    is UHF, reachable from a ground transmitter near the
 *    launch corridor.
 *  - Forge FTS_SAFE: prevent range safety from terminating a
 *    wayward vehicle. If the vehicle's autonomous GNC also
 *    fails (Starliner OFT-1-class), the FTS is the last line.
 *    Removing it creates a debris-on-population risk.
 *  - Both attacks indistinguishable from legitimate RSO
 *    commands at the AFTS crypto layer.
 *
 *  Recovery: FAA 14 CFR 417 requires cryptographic update of
 *  every AFTS flight computer in inventory + re-verification.
 *  For boosters already stacked or in transit, this is a
 *  manifest-slip measured in months.
 * --------------------------------------------------------- */
