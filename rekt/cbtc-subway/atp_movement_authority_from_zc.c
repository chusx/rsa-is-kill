/*
 * atp_movement_authority_from_zc.c
 *
 * CBTC onboard ATP (Automatic Train Protection) side: verify
 * Zone-Controller-issued movement authority, wayside object-
 * controller status, and OCC dispatcher commands. Pattern matches
 * Thales SelTrac S40, Siemens Trainguard MT, Alstom Urbalis 400,
 * Hitachi Rail STS BlueSigns.
 *
 * Runs on the train-borne Vital Computer (2oo2 voted, EN 50129
 * SIL 4). VHDL/RT-Linux hybrid in practice; C shown here.
 */

#include <stdint.h>
#include <string.h>
#include "atp.h"
#include "rsa_pss.h"
#include "rsa_pkcs1v15.h"

extern const uint8_t LINE_SIGNALLING_PKI_ROOT_PUB[384];
extern const uint8_t VENDOR_VITAL_FW_ROOT_PUB[512];
extern const uint8_t OCC_DISPATCH_ROOT_PUB[384];


/* =========================================================
 *  1. Vital-computer firmware self-verify at power-on
 * ========================================================= */

struct vital_fw_manifest {
    char      model[16];
    char      build[32];
    uint32_t  rollback_idx;
    uint8_t   atp_core_sha256[32];
    uint8_t   ato_core_sha256[32];
    uint8_t   route_db_sha256[32];   /* track database — per line */
    uint8_t   sig[512];
};

int vital_fw_self_verify(void)
{
    struct vital_fw_manifest *m = flash_read_manifest();
    if (m->rollback_idx < otp_read_rollback()) return ERR_ROLLBACK;

    uint8_t h[32];
    sha256_partition(PART_ATP, h);
    if (memcmp(h, m->atp_core_sha256, 32)) return ERR_ATP_CORE;
    sha256_partition(PART_ROUTE_DB, h);
    if (memcmp(h, m->route_db_sha256, 32)) return ERR_ROUTE_DB;

    sha256_of(m, offsetof(struct vital_fw_manifest, sig), h);
    return rsa_pkcs1v15_verify_sha256(
        VENDOR_VITAL_FW_ROOT_PUB, sizeof VENDOR_VITAL_FW_ROOT_PUB,
        (uint8_t[]){0x01,0x00,0x01}, 3,
        h, 32, m->sig, sizeof m->sig);
}


/* =========================================================
 *  2. Movement-authority from Zone Controller
 *
 *  In CBTC, ZC periodically re-issues an MA granting the train
 *  permission to move to a "limit of movement authority" (LMA).
 *  MA messages arrive at ~5 Hz over the track-radio network.
 * ========================================================= */

struct cbtc_movement_authority {
    uint32_t  zc_id;
    uint32_t  train_id;
    uint32_t  ma_seq;
    uint32_t  issued_ts_ms;
    uint32_t  lma_position_cm;        /* along line chainage */
    uint16_t  max_speed_mps_x10;
    uint16_t  profile_len;
    uint8_t   speed_profile[128];     /* encoded speed/distance curve */
    uint8_t   zc_cert[1024];
    size_t    cert_len;
    uint8_t   sig[384];
};

static uint32_t last_ma_seq_from_zc[8];   /* up to 8 overlapping ZCs */

int atp_consume_movement_authority(const struct cbtc_movement_authority *ma)
{
    if (ma->train_id != our_train_id()) return ERR_WRONG_TRAIN;

    unsigned zc_slot = ma->zc_id & 0x7;
    if (ma->ma_seq <= last_ma_seq_from_zc[zc_slot]) return ERR_REPLAY;

    /* Freshness: in CBTC, MAs older than ~1 second must cause the
     * train to start an emergency brake — the "communication loss"
     * fail-safe that underpins SIL 4 rating. */
    if (now_ms() - ma->issued_ts_ms > 1000)
        return ERR_STALE;

    if (x509_chain_verify(ma->zc_cert, ma->cert_len,
                          LINE_SIGNALLING_PKI_ROOT_PUB,
                          sizeof LINE_SIGNALLING_PKI_ROOT_PUB) != 0)
        return ERR_ZC_CHAIN;

    uint8_t n[384], e[4];
    size_t n_len, e_len;
    x509_extract_pub(ma->zc_cert, ma->cert_len,
                     n, sizeof n, &n_len, e, sizeof e, &e_len);

    uint8_t h[32];
    sha256_of(ma, offsetof(struct cbtc_movement_authority, sig), h);
    if (rsa_pss_verify_sha256(n, n_len, e, e_len,
                              h, 32, ma->sig, sizeof ma->sig) != 0)
        return ERR_MA_SIG;

    /* Plausibility: LMA inside the track database we loaded +
     * not exceeding our civil speed limits. */
    if (!lma_within_route_db(ma->lma_position_cm))    return ERR_LMA;
    if (ma->max_speed_mps_x10 >
        civil_speed_limit_at(ma->lma_position_cm))    return ERR_CIVIL;

    last_ma_seq_from_zc[zc_slot] = ma->ma_seq;
    install_ma_into_brake_curve(ma);
    return 0;
}


/* =========================================================
 *  3. OCC dispatcher command — emergency stop / mode change
 * ========================================================= */

struct occ_command {
    uint8_t   cmd;                    /* 1=ESTOP 2=SLOW 3=MODE_DEGRADED */
    uint32_t  target_train_id;        /* 0 = BROADCAST */
    uint32_t  seq;
    uint32_t  issued_ts;
    uint8_t   sig[384];
};

static uint32_t last_occ_seq;

int atp_handle_occ_command(const struct occ_command *c)
{
    if (c->seq <= last_occ_seq) return ERR_REPLAY;

    uint8_t h[32];
    sha256_of(c, offsetof(struct occ_command, sig), h);
    if (rsa_pss_verify_sha256(
            OCC_DISPATCH_ROOT_PUB, sizeof OCC_DISPATCH_ROOT_PUB,
            (uint8_t[]){0x01,0x00,0x01}, 3,
            h, 32, c->sig, sizeof c->sig) != 0)
        return ERR_OCC_SIG;

    if (c->target_train_id != 0 &&
        c->target_train_id != our_train_id()) {
        last_occ_seq = c->seq;
        return 0;
    }

    last_occ_seq = c->seq;
    switch (c->cmd) {
    case 1: apply_emergency_brake();  break;
    case 2: reduce_to_yellow_speed(); break;
    case 3: enter_degraded_mode();    break;
    }
    return 0;
}


/* ---- Breakage ---------------------------------------------
 *
 *  Line signalling PKI factored:
 *    - Forged MA messages. Overlapping moving blocks → station
 *      over-run or in-tunnel collision. SIL-4 safety case
 *      collapses; operator falls back to manual block, capacity
 *      drops ~60% on dense urban lines.
 *
 *  Vendor vital fw root factored:
 *    - Signed firmware disables brake-curve enforcement fleet-
 *      wide. Every CBTC-equipped car on the platform's lines.
 *
 *  OCC dispatch root factored:
 *    - Forged emergency-stop broadcasts deny 300,000+ commuters
 *      at peak, or forged mode-change commands push trains into
 *      degraded-manual in-tunnel.
 */
