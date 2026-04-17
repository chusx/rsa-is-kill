/*
 * cve_firmware_and_prescription.c
 *
 * Central Vehicle ECU (CVE) firmware-update receive path + ISOBUS
 * prescription-map ingestion for a large row-crop tractor. Pattern
 * matches Deere Gen4/Gen5 CommandCenter + JDLink Modem, CNH AFS
 * Pro 1200 + PLM Intelligence gateway, AGCO Fuse / JCA.
 *
 * Runs on the CVE's embedded Linux (older platforms use QNX).
 * ISO 11783 (ISOBUS) fans out to implement controllers.
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include "tractor.h"
#include "isobus.h"
#include "rsa_pkcs1v15.h"
#include "rsa_pss.h"

extern const uint8_t OEM_FW_SIGN_ROOT_PUB[512];    /* RSA-4096 */
extern const uint8_t OEM_RX_MAP_ROOT_PUB[384];     /* RSA-3072 */
extern const uint8_t OEM_OPS_CENTER_CA_PUB[384];   /* TLS leaf CA */
extern const uint8_t EPA_CAL_SIGNING_ROOT_PUB[384];/* emissions tied */


/* =========================================================
 *  1. OTA firmware bundle verify
 *
 *  A bundle contains: CVE image + N implement-ECU images
 *  (AutoTrac steering, ExactEmerge planter, AirCart meter,
 *  ProDrive CVT, SCR dosing) — each with its own sha256,
 *  one manifest signature covers all.
 * ========================================================= */

struct fw_bundle_manifest {
    char      platform[16];       /* "JD-GEN4-8R" */
    char      build[40];
    uint32_t  rollback_idx;
    uint32_t  n_images;
    struct {
        char     ecu_id[16];     /* "CVE", "AUTOTRAC", "SCR-DOSER" */
        uint32_t size;
        uint8_t  sha256[32];
    } img[64];
    uint8_t   sig[512];          /* RSA-4096 PKCS#1 v1.5 */
};

int cve_apply_ota_bundle(const uint8_t *pkg, size_t len)
{
    struct fw_bundle_manifest *m = parse_bundle_manifest(pkg, len);
    if (!m) return ERR_PARSE;

    if (m->rollback_idx < hsm_read_rollback())
        return ERR_ROLLBACK;

    uint8_t h[32];
    sha256_of(m, offsetof(struct fw_bundle_manifest, sig), h);
    if (rsa_pkcs1v15_verify_sha256(
            OEM_FW_SIGN_ROOT_PUB, sizeof OEM_FW_SIGN_ROOT_PUB,
            (uint8_t[]){0x01,0x00,0x01}, 3,
            h, 32, m->sig, sizeof m->sig) != 0)
        return ERR_BUNDLE_SIG;

    /* Emissions-strategy calibrations live under EPA/EU co-signing:
     * the cal file within the bundle must ALSO verify against the
     * EPA Tier 4 / EU Stage V root. Bypassing this voids type
     * approval and is a federal offence under CAA §203. */
    for (uint32_t i = 0; i < m->n_images; i++) {
        if (!strncmp(m->img[i].ecu_id, "SCR-DOSER", 16) ||
            !strncmp(m->img[i].ecu_id, "ECM-ENGINE", 16)) {
            if (verify_emissions_cal_signature(
                    pkg, len, &m->img[i],
                    EPA_CAL_SIGNING_ROOT_PUB,
                    sizeof EPA_CAL_SIGNING_ROOT_PUB) != 0)
                return ERR_EMISSIONS_SIG;
        }
    }

    /* Integrity-measure every image before distribution over ISOBUS
     * to the target ECU. Each ECU will re-verify on its side (the
     * pattern is defence-in-depth). */
    for (uint32_t i = 0; i < m->n_images; i++) {
        const uint8_t *p; size_t pl;
        bundle_locate_image(pkg, len, i, &p, &pl);
        sha256(p, pl, h);
        if (memcmp(h, m->img[i].sha256, 32))
            return ERR_IMAGE_HASH;
        isobus_push_image_to_ecu(m->img[i].ecu_id, p, pl);
    }

    hsm_bump_rollback();
    schedule_reboot_after_headland_turn();
    return 0;
}


/* =========================================================
 *  2. Prescription-map ingest + boundary authority
 * ========================================================= */

struct prescription_map {
    char      field_id[32];
    char      product[16];       /* "SEED", "N", "K", "FUNGICIDE" */
    uint32_t  crop_year;
    uint32_t  n_zones;
    struct {
        double lat, lon, rate;   /* WGS84 + rate per unit area */
    } zones[4096];
    uint8_t   sig[384];          /* RSA-3072 PSS-SHA256 */
};

struct field_boundary {
    char      field_id[32];
    uint32_t  n_vertices;
    struct { double lat, lon; } vertex[1024];
    uint32_t  n_exclusions;      /* waterways, endangered-species */
    struct { double lat, lon; double radius_m; } excl[64];
    uint8_t   sig[384];
};

int load_rx_map_for_field(const char *field_id)
{
    struct prescription_map pm;
    struct field_boundary fb;
    if (ops_center_fetch_rx(field_id, &pm) != 0) return ERR_NET;
    if (ops_center_fetch_boundary(field_id, &fb) != 0) return ERR_NET;

    uint8_t h[32];

    sha256_of(&pm, offsetof(struct prescription_map, sig), h);
    if (rsa_pss_verify_sha256(
            OEM_RX_MAP_ROOT_PUB, sizeof OEM_RX_MAP_ROOT_PUB,
            (uint8_t[]){0x01,0x00,0x01}, 3,
            h, 32, pm.sig, sizeof pm.sig) != 0)
        return ERR_RX_SIG;

    sha256_of(&fb, offsetof(struct field_boundary, sig), h);
    if (rsa_pss_verify_sha256(
            OEM_RX_MAP_ROOT_PUB, sizeof OEM_RX_MAP_ROOT_PUB,
            (uint8_t[]){0x01,0x00,0x01}, 3,
            h, 32, fb.sig, sizeof fb.sig) != 0)
        return ERR_BOUNDARY_SIG;

    /* Cross-check: every Rx zone falls inside the boundary AND
     * outside any exclusion (endangered-species buffers, riparian
     * setbacks). The signed boundary is the safety guard for
     * off-field application. */
    for (uint32_t i = 0; i < pm.n_zones; i++) {
        if (!point_in_boundary(&fb, pm.zones[i].lat, pm.zones[i].lon) ||
            point_in_any_exclusion(&fb, pm.zones[i].lat, pm.zones[i].lon)) {
            log_event("Rx zone %u outside signed boundary — refused", i);
            return ERR_OFF_FIELD;
        }
    }

    isobus_distribute_rx_to_implement(&pm);
    display_to_operator("Rx loaded: %s (%u zones)",
                        pm.product, pm.n_zones);
    return 0;
}


/* =========================================================
 *  3. Operations Center daily telemetry push
 * ========================================================= */

int ops_center_push_day(void)
{
    /* Mutual TLS; per-tractor RSA-2048 leaf issued at dealer
     * commissioning. Signed payload carries as-applied maps,
     * yield map, machine-health CAN snapshots, DTCs. */
    tls_t *s = tls_connect_mutual(
            OPS_CENTER_HOST,
            "/factory/tractor.crt", "/factory/tractor.key",
            OEM_OPS_CENTER_CA_PUB, sizeof OEM_OPS_CENTER_CA_PUB);
    if (!s) return -1;

    struct as_applied_record *r = spool_read_day();
    uint8_t h[32];
    sha256_of(r, as_applied_body_len(r), h);
    uint8_t sig[256];
    rsa_pkcs1v15_sign_sha256_hsm(
        TRACTOR_PRIV_HANDLE, h, 32, sig, sizeof sig);

    http_post_over_tls(s, "/ops/as-applied", r, sig);
    tls_close(s);
    return 0;
}


/* ---- Breakage ---------------------------------------------
 *
 *  OEM firmware root factored:
 *    - Fleet-wide brick / ransom during planting or harvest;
 *      multi-billion-$ yield loss. Or silent drift: seed-rate
 *      halved across a continent.
 *
 *  Rx-map root factored:
 *    - Signed over-application of nitrogen / herbicide / seed;
 *      regulatory, environmental, economic damage. Off-field
 *      spraying into endangered-species habitat.
 *
 *  Ops Center client-CA factored:
 *    - Fabricated as-applied records for USDA / EU CAP subsidy,
 *      crop insurance, RFS-2 feedstock attestation — direct
 *      federal-grant-fraud exposure.
 *
 *  EPA emissions-cal root factored:
 *    - Signed def-defeat cal, crossover with VW-style emissions
 *      scandal at fleet scale. CAA §203 federal violation
 *      exposure for every unit running it.
 */
