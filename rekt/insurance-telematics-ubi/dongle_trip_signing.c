/*
 * dongle_trip_signing.c
 *
 * OBD-II telematics dongle trip-record signing path. Runs on the
 * dongle's MCU (Cortex-M4 typical on CalAmp LMU, Geotab GO, Zubie,
 * Progressive Snapshot v3). TLS ingest to insurer backend; TPM
 * or secure-element stores the per-device RSA-2048 key.
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include "dongle.h"
#include "rsa_pss.h"
#include "rsa_pkcs1v15.h"
#include "mqtt_tls.h"

extern const uint8_t VENDOR_FW_ROOT_PUB[512];
extern const uint8_t INSURER_INGEST_CA_PUB[384];


/* =========================================================
 *  1. Firmware self-verify at power-on
 * ========================================================= */

struct dongle_fw_manifest {
    char      product[16];
    char      build[32];
    uint32_t  rollback_idx;
    uint8_t   app_sha256[32];
    uint8_t   gnss_fw_sha256[32];
    uint8_t   canbus_parser_sha256[32];
    uint8_t   sig[512];
};

int dongle_fw_self_verify(void)
{
    struct dongle_fw_manifest *m = flash_read_manifest();
    if (m->rollback_idx < otp_read_rollback()) return ERR_ROLLBACK;

    uint8_t h[32];
    sha256_partition(PART_APP, h);
    if (memcmp(h, m->app_sha256, 32)) return ERR_APP;

    sha256_of(m, offsetof(struct dongle_fw_manifest, sig), h);
    return rsa_pkcs1v15_verify_sha256(
        VENDOR_FW_ROOT_PUB, sizeof VENDOR_FW_ROOT_PUB,
        (uint8_t[]){0x01,0x00,0x01}, 3,
        h, 32, m->sig, sizeof m->sig);
}


/* =========================================================
 *  2. Trip record — captured events over the drive
 * ========================================================= */

struct trip_point {
    uint32_t  ts;              /* GNSS-disciplined */
    int32_t   lat_e7, lon_e7;
    uint16_t  speed_kph_x10;
    int16_t   accel_x_mg;      /* longitudinal, milli-g */
    int16_t   accel_y_mg;      /* lateral */
    uint8_t   flags;           /* bit0=hard_brake bit1=hard_accel bit2=swerve */
};

#define TRIP_MAX_POINTS 8192

struct trip_record {
    char       vin[17];
    char       device_serial[16];
    uint32_t   trip_id;                   /* monotonic per device */
    uint32_t   start_ts, end_ts;
    uint32_t   n_points;
    struct trip_point pts[TRIP_MAX_POINTS];
    /* Aggregate event counters the insurer actually rates on.
     * Separated so backend can verify consistency with the raw
     * polyline. */
    uint16_t   hard_brake_events;
    uint16_t   hard_accel_events;
    uint16_t   phone_handling_events;     /* via IMU phone-in-hand heuristic */
    uint16_t   speeding_over_limit_sec;   /* summed duration */
    uint32_t   night_driving_sec;
    uint8_t    device_cert[1024];
    size_t     cert_len;
    uint8_t    sig[256];                  /* RSA-2048 PSS-SHA256 */
    size_t     sig_len;
};


int seal_trip_record(struct trip_record *r)
{
    r->end_ts = (uint32_t)time(NULL);
    dongle_export_cert(r->device_cert, sizeof r->device_cert, &r->cert_len);

    uint8_t h[32];
    sha256_of(r, offsetof(struct trip_record, sig), h);
    r->sig_len = sizeof r->sig;
    return rsa_pss_sign_sha256_se(
        DEVICE_SIGNING_KEY,
        h, 32, r->sig, r->sig_len);
}


/* =========================================================
 *  3. Upload to insurer backend
 * ========================================================= */

int upload_trip_to_insurer(const struct trip_record *r)
{
    /* Mutual TLS using dongle's device cert. Backend rating engine
     * will re-verify the inner sig — defence in depth in case the
     * TLS session is unwrapped at a proxy for DPI. */
    mqtt_session_t *m = mqtt_tls_connect_mutual(
        INSURER_INGEST_BROKER,
        "/factory/dongle.crt", "/factory/dongle.key",
        INSURER_INGEST_CA_PUB, sizeof INSURER_INGEST_CA_PUB);
    if (!m) return -1;

    char topic[64];
    snprintf(topic, sizeof topic, "ubi/trips/%s/%u",
             r->device_serial, r->trip_id);
    mqtt_publish(m, topic, r, sizeof *r);
    mqtt_close(m);
    return 0;
}


/* =========================================================
 *  4. Backend (insurer-side) verifier
 *
 *  This code path actually runs in the insurer's rating-ingest
 *  service, not in the dongle. Shown here for completeness of the
 *  trust chain.
 * ========================================================= */

int insurer_verify_trip(const struct trip_record *r)
{
    /* Chain device cert to the dongle-vendor CA (which is itself
     * cross-signed into the insurer's trust bundle for this
     * product). */
    if (x509_chain_verify(r->device_cert, r->cert_len,
                          VENDOR_FW_ROOT_PUB,
                          sizeof VENDOR_FW_ROOT_PUB) != 0)
        return ERR_CHAIN;

    uint8_t n[256], e[4];
    size_t n_len, e_len;
    x509_extract_pub(r->device_cert, r->cert_len,
                     n, sizeof n, &n_len, e, sizeof e, &e_len);

    uint8_t h[32];
    sha256_of(r, offsetof(struct trip_record, sig), h);
    if (rsa_pss_verify_sha256(n, n_len, e, e_len,
                              h, 32, r->sig, r->sig_len) != 0)
        return ERR_SIG;

    /* Sanity: aggregate counters vs raw polyline. If a firmware
     * is silently dropping hard-brake flags this consistency check
     * won't catch it — that's why firmware root integrity matters. */
    uint16_t counted_hb = 0, counted_ha = 0;
    for (uint32_t i = 0; i < r->n_points; i++) {
        if (r->pts[i].flags & 0x01) counted_hb++;
        if (r->pts[i].flags & 0x02) counted_ha++;
    }
    if (counted_hb != r->hard_brake_events ||
        counted_ha != r->hard_accel_events)
        return ERR_AGGREGATE;

    rating_engine_apply(r);
    evidence_vault_archive(r);   /* subpoena-ready */
    return 0;
}


/* ---- Breakage ---------------------------------------------
 *
 *   Vendor firmware root factored:
 *     - Rogue firmware that rewrites the hard-brake flag to 0
 *       and subtracts speeding seconds. Fleet of tens of
 *       millions of dongles reports angelic driving. Insurer
 *       over-discounts ~$10B annual premium.
 *
 *   Device-issuing CA factored:
 *     - Attacker mints device certs, uploads fabricated trip
 *       histories for an adversary (harassment: plant reckless
 *       driving on an enemy), or for themselves (perfect
 *       history for discount).
 *
 *   OEM telematics root factored (OnStar etc):
 *     - Same but at OEM scale — 100M+ vehicles. Worse: forged
 *       telemetry submitted in civil-injury and criminal
 *       prosecutions as vehicle-originated evidence.
 *
 *   Commercial-telematics root factored (Samsara, Motive):
 *     - FMCSA HOS records forged; trucking firms conceal
 *       over-hours driving before fatal crashes. Insurance
 *       fraud at fleet scale; evidence integrity in crash
 *       litigation.
 */
