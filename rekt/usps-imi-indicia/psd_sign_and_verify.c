/*
 * psd_sign_and_verify.c
 *
 * Postal Security Device (PSD) indicium-signing path and USPS
 * processing-plant indicium-verify path for IMI (Intelligent Mail
 * Indicia). Pattern aligns with USPS IMI specification + UPU
 * S-series standards.
 *
 *   - psd_sign_indicium() runs inside the franking meter's PSD
 *     (Pitney Bowes Postal Security Device, Quadient IN / IS,
 *     FP myMail, Stamps.com server-side PSD).
 *   - plant_verify_indicium() runs at the USPS Network Distribution
 *     Center MLOCR / advanced-facer-canceller scanner.
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include "psd.h"
#include "imi.h"
#include "rsa_pss.h"

/* USPS-maintained trust list of PSD vendor issuing CAs. */
extern const struct psd_vendor_ca {
    char     vendor[16];           /* "PBI", "QUADIENT", "FP", "STAMPS" */
    uint8_t  ca_pub[384];          /* RSA-3072 */
    size_t   ca_len;
} USPS_PSD_TRUSTLIST[16];


/* =========================================================
 *  Meter-side: sign a piece of mail's indicium
 * ========================================================= */

struct imi_fields {
    char      meter_serial[12];       /* e.g. "PBI00123456" */
    uint32_t  ascending_register;     /* monotonic postage units used */
    uint32_t  descending_register;    /* remaining funds */
    uint32_t  piece_sequence;
    char      origin_zip[10];
    char      destination_zip[10];
    uint32_t  postage_cents;
    uint8_t   mail_class;             /* 1=FCM, 2=Priority, 3=PMEI, ... */
    uint32_t  indicium_ts;            /* epoch, per PSD RTC */
    uint8_t   reserved[4];
};

struct imi_indicium {
    struct imi_fields f;
    uint8_t  psd_cert[1024];          /* chained to vendor CA */
    size_t   cert_len;
    uint8_t  sig[384];                /* RSA-3072 PSS-SHA256 */
};


int psd_sign_indicium(struct imi_indicium *out, uint32_t postage_cents,
                      const char *dest_zip, uint8_t mail_class)
{
    /* Enforce funds + RTC sanity inside the tamper-protected PSD
     * enclosure. These checks are what make the crypto binding
     * meaningful — without a trustworthy RTC and register, the
     * signature would be over meter-controllable values. */
    if (postage_cents > funds_remaining()) return ERR_INSUFFICIENT;
    if (!rtc_within_tolerance())           return ERR_RTC;

    memset(out, 0, sizeof *out);
    strncpy(out->f.meter_serial, psd_serial(), sizeof out->f.meter_serial);
    out->f.ascending_register   = register_ascend(postage_cents);
    out->f.descending_register  = register_descend(postage_cents);
    out->f.piece_sequence       = piece_next();
    strncpy(out->f.origin_zip, psd_origin_zip(), sizeof out->f.origin_zip);
    strncpy(out->f.destination_zip, dest_zip, sizeof out->f.destination_zip);
    out->f.postage_cents        = postage_cents;
    out->f.mail_class           = mail_class;
    out->f.indicium_ts          = (uint32_t)time(NULL);

    psd_export_cert(out->psd_cert, sizeof out->psd_cert, &out->cert_len);

    uint8_t h[32];
    sha256(&out->f, sizeof out->f, h);
    /* The RSA-3072 private key is inside the PSD secure enclosure
     * and never leaves — USPS Engineering Acceptance requires a
     * FIPS 140-2 Level 3 PSD. */
    rsa_pss_sign_sha256_psd_internal(
        PSD_SIGNING_KEY_SLOT,
        h, 32,
        out->sig, sizeof out->sig);
    return 0;
}


/* =========================================================
 *  Plant-side: verify inbound indicium
 * ========================================================= */

int plant_verify_indicium(const struct imi_indicium *ind,
                          enum imi_reject_code *rej)
{
    /* 1. Locate vendor CA from the cert's issuer. */
    const struct psd_vendor_ca *vca = lookup_vendor_ca_by_issuer(
        ind->psd_cert, ind->cert_len, USPS_PSD_TRUSTLIST);
    if (!vca) { *rej = IMI_REJ_UNKNOWN_VENDOR; return -1; }

    /* 2. Chain verify the PSD cert. */
    if (x509_chain_verify(ind->psd_cert, ind->cert_len,
                          vca->ca_pub, vca->ca_len) != 0) {
        *rej = IMI_REJ_BAD_CHAIN; return -1;
    }

    /* 3. Pull out PSD public key + e. */
    uint8_t n[384], e[4];
    size_t n_len, e_len;
    x509_extract_pub(ind->psd_cert, ind->cert_len,
                     n, sizeof n, &n_len, e, sizeof e, &e_len);

    /* 4. Verify sig. */
    uint8_t h[32];
    sha256(&ind->f, sizeof ind->f, h);
    if (rsa_pss_verify_sha256(n, n_len, e, e_len,
                              h, 32, ind->sig, sizeof ind->sig) != 0) {
        *rej = IMI_REJ_BAD_SIG;
        postal_inspector_queue(ind, "bad-sig");
        return -1;
    }

    /* 5. Replay / sequence monitor. IMI plant-side DB tracks
     *    (meter_serial, piece_sequence, ascending_register) for
     *    duplicates and out-of-order insertion. */
    if (plant_db_piece_already_seen(ind->f.meter_serial,
                                    ind->f.piece_sequence)) {
        *rej = IMI_REJ_DUPLICATE;
        postal_inspector_queue(ind, "dup");
        return -1;
    }

    /* 6. Postage sufficiency for declared mail-class + weight as
     *    measured on the facer-canceller's in-line scale. */
    if (ind->f.postage_cents < minimum_for(ind->f.mail_class,
                                           measured_weight_oz())) {
        *rej = IMI_REJ_INSUFFICIENT_POSTAGE;
        return -1;
    }

    plant_db_record_seen(ind);
    return 0;
}


/* =========================================================
 *  PSD firmware update path (vendor-signed, USPS counter-signed)
 * ========================================================= */

int psd_apply_firmware_update(const uint8_t *pkg, size_t len)
{
    /* Vendor signs the image; USPS-EAL counter-signs that the
     * build is approved for deployment to US meters. Both must
     * verify inside the PSD before flashing. */
    struct psd_fw_manifest *m = parse_psd_fw(pkg, len);
    uint8_t h[32];
    sha256_of(m, offsetof(struct psd_fw_manifest, vendor_sig), h);
    if (rsa_pss_verify_sha256(
            vendor_fw_root_pub(), vendor_fw_root_len(),
            (uint8_t[]){0x01,0x00,0x01}, 3,
            h, 32, m->vendor_sig, sizeof m->vendor_sig) != 0)
        return ERR_VENDOR_SIG;

    sha256_of(m, offsetof(struct psd_fw_manifest, usps_countersig), h);
    if (rsa_pss_verify_sha256(
            USPS_EAL_ROOT_PUB, USPS_EAL_ROOT_LEN,
            (uint8_t[]){0x01,0x00,0x01}, 3,
            h, 32, m->usps_countersig,
            sizeof m->usps_countersig) != 0)
        return ERR_USPS_COUNTERSIG;

    psd_flash_and_rebind_keys(pkg, len);
    return 0;
}


/* ---- Breakage ---------------------------------------------
 *
 *   USPS PSD provisioning CA factored:
 *     - Unlimited valid indicium minting; postage-fraud scale
 *       shifts from a few $100M/year attempted to the cost of
 *       printing itself. Federal-felony case coverage swamps.
 *
 *   Vendor PSD fw root factored (Pitney Bowes, Quadient, FP):
 *     - Fleet-wide meter firmware compromise. Descending-register
 *       theft (attacker spends customers' prepaid postage),
 *       ascending-register silent inflation (revenue fraud from
 *       the meter vendor or USPS perspective).
 *
 *   UPU S-series cross-border trust anchor factored:
 *     - Forged customs declarations. Cover for contraband
 *       (drugs, weapons, sanctioned goods) moving through the
 *       international postal system.
 *
 *   PC-postage issuer CA factored (Stamps.com / Auctane):
 *     - Arbitrary forged shipping labels; e-commerce fulfilment
 *       + delivery confirmation integrity collapses globally.
 */
