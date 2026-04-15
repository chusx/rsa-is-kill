/*
 * logger_signs_excursion_log.c
 *
 * Cold-chain temperature logger: factory-installed RSA key pair
 * signs the end-of-mission excursion log. Pattern matches Sensitech
 * TempTale / ELPRO LIBERO / LogTag USRIC / Controlant Saga.
 *
 * Logger MCU is typically MSP430 or Cortex-M0 with <32 KB RAM.
 * RSA-2048 signing runs once at mission end, not per-sample.
 */

#include <stdint.h>
#include <string.h>
#include "logger.h"
#include "rsa_pss.h"

extern const uint8_t VENDOR_FW_ROOT_PUB[384];


/* =========================================================
 *  1. Firmware self-verify at reset
 * ========================================================= */

struct logger_fw_manifest {
    char      product[12];
    char      build[16];
    uint32_t  rollback_idx;
    uint8_t   app_sha256[32];
    uint8_t   sig[384];
};

int logger_fw_self_verify(void)
{
    struct logger_fw_manifest *m = flash_read_manifest();
    if (m->rollback_idx < nvm_rollback()) return ERR_ROLLBACK;

    uint8_t h[32];
    sha256_partition(PART_APP, h);
    if (memcmp(h, m->app_sha256, 32)) return ERR_APP;

    sha256_of(m, offsetof(struct logger_fw_manifest, sig), h);
    return rsa_pss_verify_sha256(
        VENDOR_FW_ROOT_PUB, sizeof VENDOR_FW_ROOT_PUB,
        (uint8_t[]){0x01,0x00,0x01}, 3,
        h, 32, m->sig, sizeof m->sig);
}


/* =========================================================
 *  2. Mission log — binds shipment identity + samples
 * ========================================================= */

#define MAX_SAMPLES 4096

struct mission_log {
    char      logger_serial[16];
    char      shipment_id[24];         /* GS1 SSCC for the pallet */
    char      lot_number[24];          /* vaccine / biologic lot */
    char      gtin[16];                /* product GTIN */
    uint32_t  start_ts;
    uint32_t  end_ts;
    uint32_t  excursion_count;
    uint32_t  n_samples;
    int16_t   temp_c_x100[MAX_SAMPLES]; /* 0.01°C resolution */
    /* Derived flags */
    int16_t   min_c_x100;
    int16_t   max_c_x100;
    uint32_t  mkt_minutes;             /* minutes above 8°C */
    uint32_t  frozen_minutes;          /* minutes below 0°C */
    uint8_t   logger_cert[1024];
    size_t    cert_len;
    uint8_t   sig[256];                /* RSA-2048 PSS-SHA256 */
};

int logger_seal_mission(struct mission_log *m)
{
    compute_excursion_statistics(m);
    logger_export_cert(m->logger_cert, sizeof m->logger_cert,
                       &m->cert_len);

    uint8_t h[32];
    sha256_of(m, offsetof(struct mission_log, sig), h);
    return rsa_pss_sign_sha256_se(
        LOGGER_SIGNING_KEY, h, 32,
        m->sig, sizeof m->sig);
}


/* =========================================================
 *  3. Wholesaler / clinic verify + dispose
 * ========================================================= */

int receive_verify_and_disposition(const struct mission_log *m,
                                    enum dispo *out)
{
    if (x509_chain_verify(m->logger_cert, m->cert_len,
                          VENDOR_FW_ROOT_PUB,
                          sizeof VENDOR_FW_ROOT_PUB) != 0)
        return ERR_CHAIN;

    uint8_t n[256], e[4];
    size_t n_len, e_len;
    x509_extract_pub(m->logger_cert, m->cert_len,
                     n, sizeof n, &n_len, e, sizeof e, &e_len);

    uint8_t h[32];
    sha256_of(m, offsetof(struct mission_log, sig), h);
    if (rsa_pss_verify_sha256(n, n_len, e, e_len,
                              h, 32, m->sig, sizeof m->sig) != 0)
        return ERR_SIG;

    /* Disposition: lot-specific temperature stability thresholds
     * come from the manufacturer's GxP profile — we look them up
     * by GTIN. mRNA products differ from routine EPI vaccines. */
    struct stability_profile sp;
    stability_lookup(m->gtin, &sp);

    if (m->max_c_x100 > sp.max_allowed_c_x100 ||
        m->min_c_x100 < sp.min_allowed_c_x100 ||
        m->mkt_minutes > sp.mkt_limit_minutes ||
        m->frozen_minutes > sp.frozen_limit_minutes) {
        *out = DISPO_QUARANTINE;
        raise_excursion_alert(m);
    } else {
        *out = DISPO_RELEASE;
    }

    archive_signed_log_for_bla(m);    /* retained 6+ years per GxP */
    return 0;
}


/* =========================================================
 *  4. Onward propagation via EPCIS to wholesaler / IIS
 * ========================================================= */

int publish_epcis_receiving_event(const struct mission_log *m)
{
    /* EPCIS ObjectEvent with bizStep=receiving + disposition.
     * The mission_log is embedded as an extension, as-is signed.
     * Downstream consumers (state IIS, IZ Gateway, PAHO Revolving
     * Fund) re-verify the logger signature before trusting the
     * trace. */
    return epcis_publish_with_extension(
        EPCIS_EVENT_RECEIVING,
        m->shipment_id, m->lot_number,
        m, sizeof *m);
}


/* ---- Breakage ---------------------------------------------
 *
 *  Logger-vendor root factored:
 *    - Signed "pristine" traces for actually-excursion-damaged
 *      lots; damaged vaccines dispensed to patients. Converse
 *      supply-attack: forge excursions on good lots, force
 *      destruction during crisis / pandemic.
 *
 *  Manufacturer dispatch-receipt root factored:
 *    - Grey-market / counterfeit biologics receive valid chain-
 *      of-custody pedigrees; pharmacy shelves contaminated.
 *
 *  IIS / IZ Gateway trust anchor factored:
 *    - Public-health vaccination statistics forgeable; forged
 *      individual-dose records (school / employer compliance).
 */
