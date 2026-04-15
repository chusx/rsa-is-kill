/*
 * ride_dispatch_and_restraints.c
 *
 * Roller-coaster ride-controller side: block-dispatch authorisation,
 * restraint-check verification, and show-controller cue-consume.
 * Pattern matches Intamin blockzone logic, Vekoma RideCtrl,
 * Mack Rides dispatch, B&M station sequencer.
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include "ride.h"
#include "rsa_pss.h"

extern const uint8_t INTEGRATOR_ROOT_PUB[384];       /* ride integrator */
extern const uint8_t SAFETY_PLC_ROOT_PUB[384];       /* TÜV-certified */
extern const uint8_t SHOWCONTROL_ROOT_PUB[384];


/* =========================================================
 *  1. Per-seat restraint-check signed telemetry
 * ========================================================= */

struct restraint_check {
    uint8_t   train_id;
    uint8_t   car_id;
    uint8_t   seat_id;                /* 1..n per car */
    uint8_t   harness_latched;        /* boolean */
    uint16_t  bar_position_deg_x10;   /* over-shoulder bar angle */
    uint16_t  weight_grams;           /* seat-pad load cell */
    uint32_t  check_ts_ms;
    uint32_t  check_seq;              /* monotonic per seat */
    uint8_t   sig[384];
};

static uint32_t last_seat_seq[8][8][4];   /* [train][car][seat] */

int ride_accept_restraint_check(const struct restraint_check *c)
{
    /* Monotonic replay guard. */
    if (c->check_seq <= last_seat_seq[c->train_id][c->car_id][c->seat_id])
        return ERR_REPLAY;

    /* Freshness — restraint check must be within 500 ms of dispatch
     * attempt. Older readings do NOT gate dispatch. */
    if (now_ms() - c->check_ts_ms > 500)
        return ERR_STALE;

    uint8_t h[32];
    sha256_of(c, offsetof(struct restraint_check, sig), h);
    if (rsa_pss_verify_sha256(
            INTEGRATOR_ROOT_PUB, sizeof INTEGRATOR_ROOT_PUB,
            (uint8_t[]){0x01,0x00,0x01}, 3,
            h, 32, c->sig, sizeof c->sig) != 0) {
        /* Safety default: a failed-verify restraint is NEVER
         * assumed secure. Dispatch inhibits. */
        operator_indicator(c->train_id, c->car_id, c->seat_id,
                           "restraint auth fail — manual verify");
        return ERR_SIG;
    }

    last_seat_seq[c->train_id][c->car_id][c->seat_id] = c->check_seq;

    if (!c->harness_latched ||
        c->bar_position_deg_x10 > MAX_OPEN_BAR_DEG_X10) {
        inhibit_dispatch(c->train_id,
            "restraint not secured T%u C%u S%u",
            c->train_id, c->car_id, c->seat_id);
    } else {
        clear_restraint_hold(c->train_id, c->car_id, c->seat_id);
    }
    return 0;
}


/* =========================================================
 *  2. Dispatch authorisation — signed by safety PLC
 *
 *  Ride controller composes a dispatch request; safety PLC returns
 *  a signed "go / no-go" after evaluating block-section status,
 *  restraint consolidation, station gate position, and e-stop
 *  chain. Safety-PLC signs — ride controller is NOT the authority.
 * ========================================================= */

struct dispatch_decision {
    uint8_t   train_id;
    uint8_t   decision;               /* 1=CLEAR 2=HOLD 3=EMERGENCY_STOP */
    uint32_t  decision_seq;
    uint32_t  issued_ms;
    uint8_t   block_state_bitmap[4];  /* per-block occupancy snapshot */
    uint8_t   sig[384];
};

static uint32_t last_dispatch_seq;

int ride_execute_dispatch(const struct dispatch_decision *d)
{
    if (d->decision_seq <= last_dispatch_seq) return ERR_REPLAY;
    if (now_ms() - d->issued_ms > 250)        return ERR_STALE;

    uint8_t h[32];
    sha256_of(d, offsetof(struct dispatch_decision, sig), h);
    if (rsa_pss_verify_sha256(
            SAFETY_PLC_ROOT_PUB, sizeof SAFETY_PLC_ROOT_PUB,
            (uint8_t[]){0x01,0x00,0x01}, 3,
            h, 32, d->sig, sizeof d->sig) != 0) {
        apply_station_brakes_emergency();
        return ERR_SAFETY_SIG;
    }

    last_dispatch_seq = d->decision_seq;

    switch (d->decision) {
    case 1: release_station_brakes(d->train_id); break;
    case 2: hold_in_station(d->train_id);        break;
    case 3: emergency_stop_all();                break;
    }
    return 0;
}


/* =========================================================
 *  3. Show-control cue consumption
 *
 *  Ride controller occasionally consumes cues from the show
 *  controller (e.g. coordinate an on-ride pyro with a launch
 *  event). Signatures bind cues to the show-control chain so an
 *  injected cue cannot trigger a pyro or water effect at the
 *  wrong moment.
 * ========================================================= */

struct show_cue {
    uint32_t  cue_id;
    uint32_t  scheduled_ms;           /* ride-local clock */
    uint16_t  action;                 /* 1=PYRO 2=WATER 3=LIGHT 4=SFX */
    uint16_t  duration_ms;
    uint32_t  intensity;
    uint8_t   sig[384];
};

int ride_consume_show_cue(const struct show_cue *c)
{
    uint8_t h[32];
    sha256_of(c, offsetof(struct show_cue, sig), h);
    if (rsa_pss_verify_sha256(
            SHOWCONTROL_ROOT_PUB, sizeof SHOWCONTROL_ROOT_PUB,
            (uint8_t[]){0x01,0x00,0x01}, 3,
            h, 32, c->sig, sizeof c->sig) != 0)
        return ERR_SHOW_SIG;

    schedule_cue(c);
    return 0;
}


/* ---- Breakage ---------------------------------------------
 *
 *  Integrator root factored:
 *    - Forged restraint-check "all secure". Train dispatches
 *      with unfastened harnesses — ejection risk on inverted /
 *      launched coasters.
 *
 *  Safety PLC TÜV root factored:
 *    - Dispatch-clear granted into occupied blocks; collision
 *      scenarios. Or emergency-stop commands forged at peak ride
 *      time (DoS, operational chaos).
 *
 *  Show-control root factored:
 *    - Pyro / water / motion cues desynchronised; burns,
 *      drowning, pyrotechnic injury to guests and cast members.
 */
