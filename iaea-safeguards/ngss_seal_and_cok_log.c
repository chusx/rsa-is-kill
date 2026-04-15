/*
 * ngss_seal_and_cok_log.c
 *
 * IAEA safeguards instrument firmware: Next-Generation Surveillance
 * System camera + Electronic Optical Seal (VACOSS-class) log-
 * signing. Runs 24/7/365 unattended between inspector visits
 * (typically 90-day cycle). Every event is signed at the moment
 * of capture so any tampering with stored records — including the
 * device's own internal storage — is detectable.
 *
 * Devices integrating this pattern: Aquila GARS, Canberra/Mirion
 * Neutron Coincidence Counter series, Arktis Radiation Detectors
 * underwater CVD, NGSS XCAM + ALIP-2020 camera head.
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include "safeguards.h"
#include "rsa_pss.h"
#include "sha256.h"

/* -- Factory-programmed device identity ------------------------- */
struct ngss_identity {
    char      device_serial[16];
    char      facility_id[32];       /* IAEA facility code, e.g. FR-LAH-RPR */
    uint8_t   device_cert[1536];     /* RSA-2048 leaf, IAEA-CA signed */
    size_t    device_cert_len;
    uint32_t  priv_handle;           /* tamper-responsive HSM slot */
};

/* -- Pinned IAEA safeguards-equipment root CA ------------------- */
extern const uint8_t IAEA_SAFEGUARDS_CA_PUB[384];  /* RSA-3072 */

/* -- Event categories written to the signed log ----------------- */
enum event_type {
    EVT_FRAME_CAPTURE  = 1,    /* new video frame from NGSS camera */
    EVT_SEAL_LOOP_OK   = 2,    /* fiber-optic seal integrity pulse */
    EVT_SEAL_BROKEN    = 3,    /* fiber loop interrupted */
    EVT_TAMPER_DETECT  = 4,    /* enclosure open, accelerometer */
    EVT_POWER_LOSS     = 5,
    EVT_POWER_RESTORE  = 6,
    EVT_SELF_TEST_OK   = 7,
    EVT_SELF_TEST_FAIL = 8,
    EVT_INSPECTOR_AUTH = 9,    /* inspector reader-card presented */
    EVT_DATA_RETRIEVED = 10,
};

struct signed_event {
    uint64_t    sequence;          /* monotonic, tamper-evident counter */
    uint32_t    event_type;
    uint64_t    timestamp_utc;     /* GPS-disciplined RTC */
    uint8_t     payload_hash[32];  /* hash of associated frame / data */
    char        device_serial[16];
    uint8_t     prev_log_chain[32];/* hash chain — see below */
    uint8_t     sig[256];          /* RSA-PSS-SHA-256 */
};

/* Append-only log with forward-hashed chain: every new event's
 * `prev_log_chain` is sha256 of the previous event's fully
 * signed representation. An attacker who wants to splice a forged
 * event into the middle of the log has to re-sign every subsequent
 * event — impossible without the device RSA private key. Making
 * the RSA private key unrecoverable is the tamper-responsive
 * hardware's job; making the RSA *math* unbreakable is where a
 * factoring attack lands. */

static struct signed_event last_event;

int ngss_sign_event(struct ngss_identity *id,
                     uint32_t event_type,
                     const uint8_t *payload, size_t payload_len)
{
    struct signed_event e = {0};
    e.sequence    = last_event.sequence + 1;
    e.event_type  = event_type;
    e.timestamp_utc = gps_disciplined_time_utc();
    sha256(payload, payload_len, e.payload_hash);
    memcpy(e.device_serial, id->device_serial, 16);

    /* Hash-chain link back to previous event (full bytes including
     * its signature). */
    uint8_t prev_hash[32];
    sha256((uint8_t *)&last_event, sizeof last_event, prev_hash);
    memcpy(e.prev_log_chain, prev_hash, 32);

    /* Hash over everything except the signature. */
    uint8_t h[32];
    sha256_of(&e, offsetof(struct signed_event, sig), h);

    if (rsa_pss_sign_sha256_hsm(id->priv_handle,
                                 h, sizeof h,
                                 e.sig, sizeof e.sig) != 0)
        return SG_HSM_FAIL;

    append_to_log_storage(&e, sizeof e);
    last_event = e;
    return SG_OK;
}


/* --- Power-on boot: self-test + announce presence --- */

int ngss_boot(struct ngss_identity *id)
{
    /* 1. Power-on self-test of RNG + sensors + HSM liveness */
    if (self_test_rng() != 0 ||
        self_test_sensors() != 0 ||
        self_test_hsm(id->priv_handle) != 0) {
        /* Log self-test failure BEFORE failing so inspector sees it. */
        ngss_sign_event(id, EVT_SELF_TEST_FAIL, NULL, 0);
        return -1;
    }
    ngss_sign_event(id, EVT_SELF_TEST_OK, NULL, 0);
    ngss_sign_event(id, EVT_POWER_RESTORE, NULL, 0);
    return 0;
}


/* --- Inspector visit: authenticate + download log --- */

int ngss_serve_inspector(struct ngss_identity *id,
                          const uint8_t *inspector_cert, size_t icl)
{
    /* Inspector presents an IAEA-issued RSA-2048 smartcard cert.
     * Chain-verify against IAEA_SAFEGUARDS_CA_PUB. */
    if (x509_chain_verify(inspector_cert, icl,
                           IAEA_SAFEGUARDS_CA_PUB,
                           sizeof IAEA_SAFEGUARDS_CA_PUB) != 0) {
        ngss_sign_event(id, EVT_INSPECTOR_AUTH, (uint8_t*)"FAIL", 4);
        return -1;
    }

    uint8_t insp_id_hash[32];
    sha256(inspector_cert, icl, insp_id_hash);
    ngss_sign_event(id, EVT_INSPECTOR_AUTH, insp_id_hash, 32);

    /* Export signed log bundle. Inspector laptop later verifies the
     * entire chain back to device cert + IAEA root at HQ Vienna. */
    export_log_over_ethernet(id);
    ngss_sign_event(id, EVT_DATA_RETRIEVED, NULL, 0);
    return 0;
}


/* --- VACOSS-style fiber-optic loop integrity check --- */

void seal_loop_integrity_task(struct ngss_identity *id)
{
    /* Runs every 1 second. A short light pulse injected into the
     * fiber must return within ns tolerance; any loss-of-continuity
     * is an immediate EVT_SEAL_BROKEN. Even a microsecond outage
     * during gamma-radiation-induced attenuation (research reactor
     * environment) causes a logged — and cryptographically
     * signed — event. */
    for (;;) {
        if (fiber_loop_pulse_and_check() == FIBER_INTACT) {
            ngss_sign_event(id, EVT_SEAL_LOOP_OK, NULL, 0);
        } else {
            ngss_sign_event(id, EVT_SEAL_BROKEN, NULL, 0);
        }
        sleep_ms(1000);
    }
}


/* ---- Breakage --------------------------------------------------
 *
 * This entire architecture depends on exactly two assumptions:
 *   (a) the RSA private key in the device HSM cannot be extracted
 *       (tamper-responsive hardware assures this), and
 *   (b) the RSA math itself is not forgeable.
 *
 * A factoring attack against the IAEA safeguards-equipment root CA
 * defeats (b). An attacker can:
 *
 *   - Mint a forged NGSS / VACOSS device cert. Replace a real
 *     seal with a forged one that signs a "seal intact" record
 *     for the entire 90-day inspector-visit gap while the real
 *     containment is opened to divert material.
 *
 *   - Fabricate an entire signed log history, matching the device
 *     serial and cert of a legitimate unit, replacing the real
 *     log at quarterly retrieval — covering diversion events.
 *     Hash-chain verifies, device-cert chains to the (forged) CA
 *     root.
 *
 *   - Mint an inspector-identity cert and query sample-tracking
 *     databases as if an authorized inspector. Internal IAEA
 *     records corruption.
 *
 * Non-proliferation's CoK architecture is one of the few places
 * in the world where *scientific non-forgeability of a signature*
 * underwrites geopolitical trust. A public break on RSA at a
 * scale where factoring 2048 or 3072-bit moduli is feasible would
 * require emergency replacement of every field instrument — a
 * coordinated program across 150+ host states that historically
 * takes IAEA DSG many years to negotiate.
 */
