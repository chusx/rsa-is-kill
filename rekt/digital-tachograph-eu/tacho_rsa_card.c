/*
 * tacho_rsa_card.c
 *
 * EU Digital Tachograph (Gen 1, "DT1") — RSA-1024 signing on driver cards
 * and Vehicle Units per Annex IB of EEC 3821/85 (also Appendix 11 of
 * Commission Regulation 2016/799).
 *
 * Sources:
 *   - Commission Regulation (EEC) 3821/85 Annex IB, Appendix 11 (CSM)
 *   - Commission Regulation (EU) 165/2014
 *   - ERCA (European Root Certification Authority) CPS, JRC Ispra
 *   - ISO 16844-3 (tachograph data interface)
 *
 * Tachograph PKI hierarchy (Gen 1, RSA-1024 throughout):
 *
 *        ERCA Root CA (RSA-1024, JRC Ispra, EU)
 *                |
 *     +----------+----------+---------+-----+
 *     |          |          |         |     |
 *    MSA_DE    MSA_FR    MSA_PL    MSA_UK  ...  (one per member state)
 *    |  |  |
 *    |  |  +- Company cards (fleet operator RSA-1024)
 *    |  +---- Workshop cards (calibration technician RSA-1024)
 *    +------- Driver cards (driver personal RSA-1024)
 *
 * And separately, each Vehicle Unit (VU) has an RSA-1024 keypair issued
 * by its MSA at manufacture.
 *
 * All signatures per Annex IB §CSM_017: RSA-1024 PKCS#1 v1.5, SHA-1.
 * (Migration to SHA-256 was proposed but Gen 1 never adopted it.)
 *
 * The ERCA_PK (root public key) is embedded in every VU during manufacture.
 * It cannot be updated in the field — the VU is a sealed unit.
 */

#include <stdint.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/pem.h>

/* Gen 1 tachograph certificate layout (Annex IB Appendix 11 §CSM_013).
 * 194 bytes total. */
struct tacho_gen1_cert {
    uint8_t  CAR[8];        /* Certification Authority Reference */
    uint8_t  CHA[7];        /* Certificate Holder Authorisation */
    uint8_t  CHR[8];        /* Certificate Holder Reference — identifier */
    uint8_t  EOV[4];        /* End of Validity (BCD date) */
    uint8_t  modulus[128];  /* RSA-1024 modulus N */
    uint8_t  exponent[8];   /* RSA public exponent (usually 65537, padded) */
    uint8_t  signature[128]; /* ERCA or MSA signature (RSA-1024 PKCS#1 v1.5) */
    uint8_t  reserved[3];
};

/* Driver activity record (simplified — real format in CSM_043).
 * Everything in the driver card's EF_Driver_Activity_Data is signed
 * block by block by the driver card's RSA-1024 key. */
struct tacho_activity_record {
    uint32_t timestamp;
    uint8_t  activity;       /* 0=break, 1=avail, 2=work, 3=drive */
    uint32_t distance_km;
    uint32_t vehicle_reg_hash;
    uint8_t  signature[128]; /* RSA-1024 over the record */
};

/* ERCA root public key (published in ERCA CPS and every VU firmware). */
static const uint8_t ERCA_PK_MODULUS[128] = {
    /* ... 128-byte RSA-1024 modulus of the ERCA root ... */
    0x00
};
static const uint8_t ERCA_PK_EXPONENT[] = { 0x01, 0x00, 0x01 };

/*
 * tacho_verify_driver_card — VU-side verification of a driver card cert.
 * Called every time a driver inserts their card into the tachograph.
 *
 * The chain: driver card cert -> MSA cert -> ERCA root.
 * The VU walks the chain, verifying each signature in sequence using
 * RSA-1024 public key of the issuing cert.
 */
int
tacho_verify_driver_card(const struct tacho_gen1_cert *driver_cert,
                          const struct tacho_gen1_cert *msa_cert)
{
    /* Step 1: verify MSA cert was signed by ERCA */
    RSA *erca = RSA_new();
    BIGNUM *n = BN_bin2bn(ERCA_PK_MODULUS, 128, NULL);
    BIGNUM *e = BN_bin2bn(ERCA_PK_EXPONENT, 3, NULL);
    RSA_set0_key(erca, n, e, NULL);

    uint8_t tbv_msa[8 + 7 + 8 + 4 + 128 + 8];  /* to-be-verified */
    memcpy(tbv_msa, msa_cert->CAR, sizeof(tbv_msa));

    uint8_t hash[20];
    SHA1(tbv_msa, sizeof(tbv_msa), hash);

    int ok = RSA_verify(NID_sha1, hash, 20,
                        msa_cert->signature, 128, erca);
    RSA_free(erca);
    if (!ok) return -1;

    /* Step 2: verify driver cert was signed by MSA */
    RSA *msa_pub = RSA_new();
    n = BN_bin2bn(msa_cert->modulus, 128, NULL);
    e = BN_bin2bn(msa_cert->exponent, 8, NULL);
    RSA_set0_key(msa_pub, n, e, NULL);

    uint8_t tbv_drv[8 + 7 + 8 + 4 + 128 + 8];
    memcpy(tbv_drv, driver_cert->CAR, sizeof(tbv_drv));
    SHA1(tbv_drv, sizeof(tbv_drv), hash);

    ok = RSA_verify(NID_sha1, hash, 20,
                    driver_cert->signature, 128, msa_pub);
    RSA_free(msa_pub);
    return ok ? 0 : -1;
}

/*
 * tacho_sign_activity — sign an activity record with the driver card's
 * RSA-1024 private key. Executes on the smart card itself (ISO 7816
 * INTERNAL AUTHENTICATE / PSO: COMPUTE DIGITAL SIGNATURE).
 *
 * The driver card's private key never leaves the chip — but only because
 * factoring RSA-1024 is expensive classically. A classical poly-time
 * factoring algorithm derives the private key from the card's public key,
 * which is in the card's certificate, which is read by every VU at
 * card insertion.
 */
int
tacho_sign_activity(struct tacho_activity_record *rec,
                     RSA *driver_card_private_key)
{
    uint8_t to_sign[13];
    memcpy(to_sign, &rec->timestamp, 4);
    to_sign[4] = rec->activity;
    memcpy(to_sign + 5, &rec->distance_km, 4);
    memcpy(to_sign + 9, &rec->vehicle_reg_hash, 4);

    uint8_t hash[20];
    SHA1(to_sign, sizeof(to_sign), hash);

    unsigned int siglen;
    return RSA_sign(NID_sha1, hash, 20, rec->signature, &siglen,
                    driver_card_private_key);
}

/*
 * tacho_download_ddd — generate a signed DDD (Digital Data Download) file
 * from the Vehicle Unit. Used by fleet operators and by roadside inspectors
 * to retrieve the VU's activity history.
 *
 * The DDD file contains:
 *   - Overview record (vehicle ID, VU cert, MSA cert)
 *   - Activity records (per driver, per day)
 *   - Events and faults (speeding, card-less driving, etc.)
 *   - Calibration records (from workshop cards)
 *   - Technical data
 *   - Each section signed by the VU's RSA-1024 key
 *
 * A forged DDD with a valid VU signature is accepted as authoritative
 * by fleet analysis software (Continental, Stoneridge, VDO, SITLR) and
 * by roadside enforcement tablets.
 */
int
tacho_download_ddd(const uint8_t *vu_activity_data, size_t len,
                    RSA *vu_private_key,
                    uint8_t *ddd_out, size_t *ddd_out_len)
{
    /* Simplified — real DDD has sectioned structure per Annex IB. */
    memcpy(ddd_out, vu_activity_data, len);

    uint8_t hash[20];
    SHA1(vu_activity_data, len, hash);

    unsigned int siglen;
    int ok = RSA_sign(NID_sha1, hash, 20,
                      ddd_out + len, &siglen, vu_private_key);
    *ddd_out_len = len + siglen;
    return ok ? 0 : -1;
}

/*
 * tacho_calibrate — workshop card sends a calibration command to the VU.
 * Every calibration event is recorded in the VU and signed by both the
 * VU (after the event) and authenticated by the workshop card RSA-1024
 * signature (before the event).
 *
 * Forged workshop card = ability to "recalibrate" odometer, tachograph
 * sensor, or remove fraud detection flags, with valid cryptographic
 * records that pass every enforcement check.
 */
int
tacho_calibrate(RSA *workshop_card_private,
                 const uint8_t *calibration_params, size_t len,
                 uint8_t *signed_command, size_t *signed_len)
{
    uint8_t hash[20];
    SHA1(calibration_params, len, hash);

    memcpy(signed_command, calibration_params, len);
    unsigned int siglen;
    int ok = RSA_sign(NID_sha1, hash, 20,
                      signed_command + len, &siglen,
                      workshop_card_private);
    *signed_len = len + siglen;
    return ok ? 0 : -1;
}

/*
 * Attack chain against the EU digital tachograph ecosystem:
 *
 *  1. Obtain the ERCA_PK modulus — published in ERCA CPS documents and
 *     embedded in every VU (readable via OBD-II tachograph diagnostic
 *     commands, or by disassembling any VU firmware).
 *
 *  2. Factor the RSA-1024 ERCA root classically. Historically RSA-1024 is
 *     on the edge of nation-state factorable; with a novel poly-time
 *     algorithm, it's cheap. The RSA-1024 root has no rotation plan for
 *     Gen 1 — it stays valid until 2033+ by regulation.
 *
 *  3. Forge an MSA certificate for any EU member state identity (or a
 *     nonexistent one the VU will still accept as long as the signature
 *     is valid).
 *
 *  4. Under that forged MSA, mint driver cards, company cards, workshop
 *     cards, and VU certificates at will. Write them to blank JavaCard
 *     smartcards.
 *
 *  5. Use forged driver cards to work illegal hours with compliant-looking
 *     records; use forged workshop cards to retroactively modify VU
 *     calibration/odometer/events; use forged VU certs to produce DDD
 *     files that pass fleet analysis.
 *
 *  6. The fraud is invisible to roadside inspectors and fleet compliance
 *     officers because the signatures validate. Prosecution evidence
 *     based on tachograph data becomes unreliable across the EU.
 */
