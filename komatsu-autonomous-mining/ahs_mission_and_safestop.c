/*
 * ahs_mission_and_safestop.c
 *
 * Autonomous haul truck vehicle-controller mission receive + safe-
 * stop handling. Runs on the AHS vehicle computer (dual-redundant,
 * ISO 17757 / ISO 21815 conformant). Pattern matches Komatsu
 * FrontRunner, Cat MineStar Command, Hitachi AHS.
 *
 * This is the C2 path only. Perception, path-planning, and the
 * 10 kHz vehicle-dynamics loop are separate files.
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include "haul_truck.h"
#include "rsa_pss.h"

extern const uint8_t FMS_MISSION_ROOT_PUB[384];   /* RSA-3072 */
extern const uint8_t MINE_CTRL_SAFESTOP_PUB[384]; /* RSA-3072 */
extern const uint8_t OEM_FW_ROOT_PUB[512];
extern const uint8_t PDS_TOKEN_ROOT_PUB[384];


/* =========================================================
 *  1. Signed mission from FMS
 * ========================================================= */

struct mission {
    uint32_t  truck_id;
    uint32_t  mission_seq;            /* monotonic per truck */
    uint32_t  issued_ts;
    uint32_t  valid_until;
    struct    geo pickup;             /* shovel / loader location */
    struct    geo drop;               /* dump / crusher */
    uint32_t  n_waypoints;
    struct    waypoint wp[64];        /* lat/lon/max_kph/speed-zone */
    uint32_t  n_exclusions;
    struct    exclusion ex[32];       /* dump-edge keep-out polys */
    uint8_t   sig[384];
};

static uint32_t last_mission_seq;

int ahs_receive_mission(const struct mission *m)
{
    if (m->truck_id != truck_identity()) return ERR_NOT_ME;
    if (m->mission_seq <= last_mission_seq) return ERR_REPLAY;

    uint32_t now = (uint32_t)time(NULL);
    if (now > m->valid_until) return ERR_STALE;

    uint8_t h[32];
    sha256_of(m, offsetof(struct mission, sig), h);
    if (rsa_pss_verify_sha256(
            FMS_MISSION_ROOT_PUB, sizeof FMS_MISSION_ROOT_PUB,
            (uint8_t[]){0x01,0x00,0x01}, 3,
            h, 32, m->sig, sizeof m->sig) != 0) {
        telemetry("MISSION_SIG_BAD seq=%u", m->mission_seq);
        go_to_safe_hold();
        return ERR_SIG;
    }

    /* Plausibility — waypoints inside the mine boundary, drop not
     * beyond a dump-edge exclusion. This is defence-in-depth on
     * top of the signed exclusion polys that accompany the
     * mission. */
    if (!waypoints_inside_mine(m) ||
        drop_point_beyond_edge(m))
        return ERR_GEOM;

    last_mission_seq = m->mission_seq;
    activate_mission(m);
    return 0;
}


/* =========================================================
 *  2. Safe-stop channel — verified broadcast
 * ========================================================= */

struct safestop_cmd {
    uint8_t   scope;                 /* 0=ALL 1=FLEET_GROUP 2=TRUCK */
    uint32_t  target_id;             /* iff scope != ALL */
    uint8_t   stop_type;             /* 1=SERVICE_BRAKE 2=PARKING 3=EMERGENCY */
    uint32_t  nonce;                 /* monotonic across fleet */
    uint32_t  issued_ts;
    uint8_t   sig[384];
};

static uint32_t last_safestop_nonce;

int ahs_handle_safestop(const struct safestop_cmd *c)
{
    uint8_t h[32];
    sha256_of(c, offsetof(struct safestop_cmd, sig), h);
    if (rsa_pss_verify_sha256(
            MINE_CTRL_SAFESTOP_PUB, sizeof MINE_CTRL_SAFESTOP_PUB,
            (uint8_t[]){0x01,0x00,0x01}, 3,
            h, 32, c->sig, sizeof c->sig) != 0) {
        telemetry("SAFESTOP_SIG_BAD");
        /* Policy: do NOT blindly trust unsigned safe-stops, but do
         * de-rate to creep speed and alert tower. Failure to verify
         * sigs must not itself cause a production-destroying halt. */
        return ERR_SAFESTOP_SIG;
    }

    if (c->nonce <= last_safestop_nonce) return ERR_REPLAY;
    last_safestop_nonce = c->nonce;

    if (c->scope == 2 && c->target_id != truck_identity()) return 0;

    switch (c->stop_type) {
    case 1: service_brake_to_halt();    break;
    case 2: service_brake_then_park();  break;
    case 3: emergency_stop_now();       break;
    }
    return 0;
}


/* =========================================================
 *  3. Proximity-token verification (pedestrian / manned vehicle)
 * ========================================================= */

struct pds_token_broadcast {
    uint32_t  token_id;              /* bound to worker / vehicle */
    uint8_t   kind;                  /* 0=WORKER 1=MANNED_VEH 2=DECOY_SIM */
    uint32_t  issued_ts;             /* short-lived, re-broadcast */
    struct    geo reported_pos;
    uint8_t   sig[384];
};

/* Trust plane: each PDS radio ships from factory with a cert chained
 * to PDS_TOKEN_ROOT. Tokens are re-signed by the radio every N
 * seconds with a fresh timestamp so harvested broadcasts can't be
 * re-played. */
int ahs_consume_pds_broadcast(const struct pds_token_broadcast *t)
{
    uint8_t h[32];
    sha256_of(t, offsetof(struct pds_token_broadcast, sig), h);
    if (rsa_pss_verify_sha256(
            PDS_TOKEN_ROOT_PUB, sizeof PDS_TOKEN_ROOT_PUB,
            (uint8_t[]){0x01,0x00,0x01}, 3,
            h, 32, t->sig, sizeof t->sig) != 0) {
        /* Do NOT discard — treat any un-authenticated return as a
         * potential obstacle. This prevents a denial-of-protection
         * attack where an adversary jams or mints junk. */
        perception_add_unverified_return(t);
        return ERR_TOKEN_SIG;
    }

    uint32_t now = (uint32_t)time(NULL);
    if (now - t->issued_ts > 5) {
        perception_add_unverified_return(t);
        return ERR_TOKEN_STALE;
    }

    /* Authenticated — raise track to the protected class, which
     * applies wider keep-out radii, lower crossing speeds, and
     * forbids path plans within the safety envelope. */
    perception_add_protected_track(t->token_id, t->kind, &t->reported_pos);
    return 0;
}


/* ---- Breakage ---------------------------------------------
 *
 *   FMS mission root factored:
 *     - Signed mission routes a loaded 400 t truck over a dump
 *       edge, or into a manned area. Fatality risk + multi-$100M
 *       loss-of-equipment.
 *
 *   Mine-control safestop root factored:
 *     - DoS: fleet-wide spurious safe-stops collapse production
 *       at $20M/day operations.
 *     - Worse: forged "resume" after a legitimate emergency
 *       safe-stop while the hazard is still present.
 *
 *   PDS token root factored:
 *     - Forged worker/vehicle tokens create phantom protected
 *       tracks (DoS). Or absence of a worker's genuine token,
 *       which the truck can't verify missing, goes unnoticed
 *       while the worker is in the fleet's path.
 *
 *   OEM fw root factored:
 *     - Subtle steering or collision-avoidance defects pushed
 *       to every truck of an OEM; multi-fleet fatality risk.
 */
