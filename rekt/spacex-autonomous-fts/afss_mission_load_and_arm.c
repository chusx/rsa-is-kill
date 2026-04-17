/*
 * afss_mission_load_and_arm.c
 *
 * Autonomous Flight Safety System (AFSS) boot-to-arm sequence for an
 * orbital-class launcher. Runs on the AFSS primary + secondary
 * processors (triple-redundant, voting). Pattern matches the
 * RCC 319-19 compliant AFSS on Falcon 9/Heavy, Vulcan, New Glenn,
 * Neutron, Terran R.
 *
 * This is the pre-flight and arm-sequence path. The in-flight
 * autonomous decision loop (IIP vs corridor polygon, impact-limit
 * lines, gate crossings) is in afss_autonomous_decision.c.
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include "afss.h"
#include "rsa_pss.h"
#include "rsa_pkcs1v15.h"

/* ---- Factory-burned trust anchors (in AFSS PROM) ----------------- */
extern const uint8_t RANGE_CMD_DESTRUCT_PUB[512];   /* RSA-4096 */
extern const uint8_t RANGE_MISSION_LOAD_PUB[512];   /* RSA-4096 */
extern const uint8_t VENDOR_AFSS_FW_ROOT_PUB[512];  /* RSA-4096 */

enum afss_state {
    AFSS_SAFE = 0,
    AFSS_LOADED,
    AFSS_ARMED,
    AFSS_FLIGHT,
    AFSS_TERMINATED,
};


/* ==================================================================
 *  1. Power-on self-verify of the AFSS flight software itself
 * ================================================================== */

struct afss_fw_manifest {
    char      vehicle[16];        /* "FALCON9-B1095" */
    char      build[32];
    uint32_t  rollback_idx;
    uint8_t   primary_sha256[32];
    uint8_t   secondary_sha256[32];
    uint8_t   voter_sha256[32];
    uint8_t   sig[512];           /* RSA-4096 PSS-SHA256 */
};

int afss_fw_self_verify(void)
{
    struct afss_fw_manifest *m = prom_read_manifest();

    if (m->rollback_idx < otp_read_rollback())
        return ERR_ROLLBACK;

    uint8_t h[32];
    sha256_partition(PART_AFSS_PRIMARY, h);
    if (memcmp(h, m->primary_sha256, 32)) return ERR_PRIMARY_CORRUPT;
    sha256_partition(PART_AFSS_SECONDARY, h);
    if (memcmp(h, m->secondary_sha256, 32)) return ERR_SECONDARY_CORRUPT;
    sha256_partition(PART_AFSS_VOTER, h);
    if (memcmp(h, m->voter_sha256, 32)) return ERR_VOTER_CORRUPT;

    sha256_of(m, offsetof(struct afss_fw_manifest, sig), h);
    return rsa_pss_verify_sha256(
        VENDOR_AFSS_FW_ROOT_PUB, sizeof VENDOR_AFSS_FW_ROOT_PUB,
        (uint8_t[]){0x01,0x00,0x01}, 3,
        h, 32, m->sig, sizeof m->sig);
}


/* ==================================================================
 *  2. Mission-load verify (corridor polygon, gate set, impact lines)
 * ================================================================== */

struct mission_load {
    char      mission_id[24];       /* "USSF-124" */
    uint32_t  t0_epoch;             /* liftoff time window start */
    uint32_t  window_close_epoch;
    uint32_t  n_corridor_vertices;
    struct    geo_point corridor[256];   /* lat/lon polygon */
    uint32_t  n_gates;
    struct    gate_spec gates[32];        /* time-vs-alt gates */
    uint32_t  n_impact_lines;
    struct    impact_line iils[16];       /* protected zones */
    uint8_t   sig[512];
};

int afss_load_mission(const struct mission_load *ml)
{
    /* Range-safety engineering signs the mission file. The AFSS
     * refuses to arm without a valid signature AND a liftoff window
     * that covers the current time. */
    uint8_t h[32];
    sha256_of(ml, offsetof(struct mission_load, sig), h);
    if (rsa_pss_verify_sha256(
            RANGE_MISSION_LOAD_PUB, sizeof RANGE_MISSION_LOAD_PUB,
            (uint8_t[]){0x01,0x00,0x01}, 3,
            h, 32, ml->sig, sizeof ml->sig) != 0)
        return ERR_MISSION_SIG;

    uint32_t now = (uint32_t)time(NULL);
    if (now + SAFETY_LEAD_MARGIN > ml->window_close_epoch)
        return ERR_WINDOW_PAST;

    if (ml->n_corridor_vertices < 3 ||
        ml->n_corridor_vertices > 256)
        return ERR_CORRIDOR_MALFORMED;

    copy_corridor_to_ram(ml);
    set_state(AFSS_LOADED);
    telemetry_event("MISSION_LOAD_OK mission=%s vertices=%u gates=%u",
                    ml->mission_id, ml->n_corridor_vertices, ml->n_gates);
    return 0;
}


/* ==================================================================
 *  3. Arm command from range
 * ==================================================================
 *
 * Arm is commanded from the range Command Destruct Transmitter (CDT),
 * signed by the range-safety-officer's HSM. AFSS verifies the
 * command against RANGE_CMD_DESTRUCT_PUB, checks the mission_id +
 * nonce match the currently-loaded mission, and only then transitions
 * SAFE→ARMED.
 */

struct range_cmd {
    uint8_t   cmd_type;            /* 1=ARM 2=DISARM 3=DESTRUCT 4=ABORT */
    char      mission_id[24];
    uint64_t  nonce;               /* monotonic, persisted */
    uint32_t  issued_ts;
    uint8_t   sig[512];            /* RSA-4096 PKCS#1 v1.5 */
};

static uint64_t last_nonce_seen;   /* persisted to rad-hard NVM */

int afss_handle_range_cmd(const struct range_cmd *c)
{
    uint8_t h[32];
    sha256_of(c, offsetof(struct range_cmd, sig), h);
    if (rsa_pkcs1v15_verify_sha256(
            RANGE_CMD_DESTRUCT_PUB, sizeof RANGE_CMD_DESTRUCT_PUB,
            (uint8_t[]){0x01,0x00,0x01}, 3,
            h, 32, c->sig, sizeof c->sig) != 0) {
        telemetry_event("RANGE_CMD_SIG_BAD type=%u", c->cmd_type);
        return ERR_CMD_SIG;
    }

    if (c->nonce <= last_nonce_seen) {
        telemetry_event("RANGE_CMD_REPLAY nonce=%llu", c->nonce);
        return ERR_REPLAY;
    }
    last_nonce_seen = c->nonce;
    nvm_persist(&last_nonce_seen, sizeof last_nonce_seen);

    if (strncmp(c->mission_id, current_mission_id(), 24))
        return ERR_WRONG_MISSION;

    switch (c->cmd_type) {
    case 1:  /* ARM */
        if (get_state() != AFSS_LOADED) return ERR_STATE;
        set_state(AFSS_ARMED);
        telemetry_event("AFSS_ARMED nonce=%llu", c->nonce);
        break;
    case 2:  /* DISARM — only before liftoff */
        if (get_state() != AFSS_ARMED) return ERR_STATE;
        if (sensors_say_airborne()) return ERR_AIRBORNE;
        set_state(AFSS_LOADED);
        break;
    case 3:  /* DESTRUCT */
        /* Only executes if we're in ARMED or FLIGHT. This is a
         * backup path; primary destruct is autonomous IIP logic. */
        if (get_state() != AFSS_ARMED && get_state() != AFSS_FLIGHT)
            return ERR_STATE;
        fire_destruct_charges();
        set_state(AFSS_TERMINATED);
        break;
    case 4:  /* HOLD / ABORT — pre-liftoff */
        vehicle_hold();
        break;
    }
    return 0;
}


/* ---- Breakage ------------------------------------------------
 *
 *  Factored RANGE_CMD_DESTRUCT key:
 *    - Rogue transmitter issues a signed DESTRUCT command to a
 *      vehicle mid-ascent. Loss of vehicle, crew, payload; debris
 *      liability. Or signs a spoofed DISARM before liftoff,
 *      preventing autonomous destruct on a subsequent deviation.
 *
 *  Factored RANGE_MISSION_LOAD key:
 *    - Attacker pushes a corridor polygon with a coastline-
 *      overlapping extension; autonomous logic permits a
 *      deviated trajectory to reach populated land before
 *      triggering destruct.
 *
 *  Factored VENDOR_AFSS_FW root:
 *    - Signed AFSS flight software with autonomous-destruct
 *      logic disabled, or with the IIP projection arithmetic
 *      silently offset. Range safety case collapses; FAA
 *      Part 450 launch licences suspended fleet-wide pending
 *      re-verification.
 */
