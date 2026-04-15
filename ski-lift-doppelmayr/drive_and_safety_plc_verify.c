/*
 * drive_and_safety_plc_verify.c
 *
 * Ropeway drive-cabinet PLC firmware self-verify, safety-PLC
 * separate-chain verify, and grip-telemetry authentication.
 * Pattern aligns with Doppelmayr DIRECT Drive / CONNECT monitoring,
 * Leitner DirectDrive + Leitop service link.
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include "ropeway.h"
#include "rsa_pss.h"
#include "rsa_pkcs1v15.h"

extern const uint8_t PLC_VENDOR_ROOT_PUB[512];       /* Siemens / Beckhoff */
extern const uint8_t SAFETY_PLC_TUV_ROOT_PUB[384];   /* F-CPU / Pilz */
extern const uint8_t OEM_ROPEWAY_ROOT_PUB[384];      /* Doppelmayr / Leitner */


/* =========================================================
 *  1. Drive PLC firmware verify
 * ========================================================= */

struct drive_plc_fw {
    char      platform[16];           /* "S7-1516F" */
    char      build[24];
    uint32_t  rollback_idx;
    uint8_t   app_sha256[32];
    uint8_t   motor_ctrl_sha256[32];
    uint8_t   sig[512];
};

int drive_plc_self_verify(void)
{
    struct drive_plc_fw *m = flash_read_drive_fw();
    if (m->rollback_idx < otp_rollback()) return ERR_ROLLBACK;

    uint8_t h[32];
    sha256_partition(PART_DRIVE_APP, h);
    if (memcmp(h, m->app_sha256, 32)) return ERR_APP;

    sha256_of(m, offsetof(struct drive_plc_fw, sig), h);
    return rsa_pkcs1v15_verify_sha256(
        PLC_VENDOR_ROOT_PUB, sizeof PLC_VENDOR_ROOT_PUB,
        (uint8_t[]){0x01,0x00,0x01}, 3,
        h, 32, m->sig, sizeof m->sig);
}


/* =========================================================
 *  2. Safety-PLC firmware verify — distinct TÜV chain
 *
 *  EN 13243 requires overspeed, emergency-brake, wind, anti-
 *  rollback interlocks on a CAT 3 / PL e channel independent of
 *  drive logic. Different signing chain so a drive-PLC key
 *  compromise cannot authoritatively reach safety.
 * ========================================================= */

struct safety_plc_fw {
    char      build[24];
    uint32_t  rollback_idx;
    uint8_t   overspeed_sha256[32];
    uint8_t   brake_sha256[32];
    uint8_t   wind_interlock_sha256[32];
    uint8_t   rollback_sha256[32];
    uint8_t   sig[384];
};

int safety_plc_self_verify(void)
{
    struct safety_plc_fw *m = safety_read_fw();
    if (m->rollback_idx < safety_otp_rollback()) return ERR_ROLLBACK;

    uint8_t h[32];
    sha256_of(m, offsetof(struct safety_plc_fw, sig), h);
    return rsa_pss_verify_sha256(
        SAFETY_PLC_TUV_ROOT_PUB, sizeof SAFETY_PLC_TUV_ROOT_PUB,
        (uint8_t[]){0x01,0x00,0x01}, 3,
        h, 32, m->sig, sizeof m->sig);
}


/* =========================================================
 *  3. Grip-unit telemetry — per-chair/gondola
 * ========================================================= */

struct grip_telemetry {
    uint32_t  grip_serial;
    uint32_t  carrier_id;             /* chair/gondola on this line */
    uint32_t  ts_ms;
    uint16_t  grip_force_n;
    uint16_t  slippage_mm_x100;
    uint8_t   door_latch_closed;
    uint8_t   restraint_bar_down;
    uint8_t   sig[384];
};

int bottom_station_accept_grip_telemetry(const struct grip_telemetry *t)
{
    uint8_t h[32];
    sha256_of(t, offsetof(struct grip_telemetry, sig), h);
    if (rsa_pss_verify_sha256(
            OEM_ROPEWAY_ROOT_PUB, sizeof OEM_ROPEWAY_ROOT_PUB,
            (uint8_t[]){0x01,0x00,0x01}, 3,
            h, 32, t->sig, sizeof t->sig) != 0) {
        /* Safety default: unverifiable telemetry must not be
         * used to mask a fault. Treat as loss-of-telemetry and
         * flag for the operator. */
        raise_alarm("grip-telemetry auth failure grip=%u",
                    t->grip_serial);
        return ERR_SIG;
    }

    if (t->grip_force_n < MIN_GRIP_FORCE_N ||
        t->slippage_mm_x100 > MAX_SLIPPAGE_X100) {
        escalate_to_safety_plc(STOP_LINE_CONTROLLED,
                               "grip anomaly");
    }

    if (!t->door_latch_closed || !t->restraint_bar_down) {
        if (gondola_near_station(t->carrier_id))
            return 0;                 /* expected while unloading */
        escalate_to_safety_plc(STOP_LINE_EMERGENCY,
                               "open door in flight");
    }
    return 0;
}


/* =========================================================
 *  4. Vendor remote-service link (Doppelmayr CONNECT / Leitop)
 * ========================================================= */

int vendor_remote_service_connect(void)
{
    /* Mutual TLS to OEM cloud. Drive cabinet holds an RSA-2048
     * client cert issued at installation commissioning. Only
     * read-only diagnostic is permitted; write actions require a
     * local operator-keyed handshake. */
    return mqtt_tls_connect_mutual(
        OEM_CONNECT_BROKER,
        "/installation/drive.crt",
        "/installation/drive.key",
        OEM_ROPEWAY_ROOT_PUB, sizeof OEM_ROPEWAY_ROOT_PUB);
}


/* ---- Breakage ---------------------------------------------
 *
 *  PLC vendor root factored (Siemens / Beckhoff / Rockwell):
 *    - Signed drive firmware mis-tunes stopping distance or
 *      acceleration ramp; chair ejection at terrain load or
 *      cable de-ropement.
 *
 *  Safety-PLC TÜV root factored:
 *    - The independent safety channel's own firmware is compromised;
 *      overspeed / brake / wind interlocks can be subverted. The
 *      EN 13243 safety case collapses on the affected fleet.
 *
 *  OEM ropeway root factored (Doppelmayr / Leitner):
 *    - Grip-telemetry forgeries conceal failing grips before
 *      detachment; remote-service push alters drive profile at
 *      scale. Mass-casualty risk (Stresa-Mottarone 2021 class).
 */
