/*
 * Illustrative code based on ICAO Doc 9303 Part 11 (e-Passport security mechanisms).
 * E-passports (ICAO 9303, ISO/IEC 14443) use RSA or ECDSA for:
 *   - Passive Authentication (PA): Document Security Object (SOD) signed by Country Signing CA
 *   - Active Authentication (AA): RSA-1024 or RSA-2048 challenge-response in chip
 *   - Chip Authentication (CA): ECDH or DH for secure messaging
 *   - Terminal Authentication (TA): ECDSA for inspection system authorization
 *
 * ~1.2 billion e-passports are in circulation globally (2024).
 * Passport validity: 10 years. Chips cannot be updated after issuance.
 * No PQC mechanism is defined in ICAO 9303 or the BSI TR-03110 spec.
 */

#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

/*
 * Passive Authentication — verify the Document Security Object (SOD).
 * The SOD is a CMS SignedData structure signed by the Country Signing CA (CSCA).
 * Most CSCAs use RSA-2048 or RSA-4096. A few newer ones use ECDSA.
 * The SOD contains SHA-256 hashes of all data groups (DG1..DG16).
 * Breaking the CSCA RSA key allows forging any passport from that country.
 */
int icao_passive_authentication(const uint8_t *sod_data, size_t sod_len,
                                X509_STORE *csca_store)
{
    CMS_ContentInfo *cms = NULL;
    BIO *sod_bio = BIO_new_mem_buf(sod_data, sod_len);
    int ret = -1;

    /* Parse the CMS SignedData from the SOD (EF.SOD) */
    cms = d2i_CMS_bio(sod_bio, NULL);
    if (!cms) goto done;

    /*
     * Verify signature — if CSCA uses RSA-2048, this calls RSA_verify().
     * A CRQC can factor the CSCA public key and forge the SOD for any
     * passport from that country. All ~195 countries' CSCAs are at risk.
     */
    ret = CMS_verify(cms, NULL, csca_store, NULL, NULL, 0);

done:
    CMS_ContentInfo_free(cms);
    BIO_free(sod_bio);
    return ret;
}

/*
 * Active Authentication — RSA challenge-response on the chip.
 * Defined in ICAO 9303 Part 11 §4.3.
 * The chip holds an RSA-1024 or RSA-2048 private key burned at manufacture.
 * The terminal sends a random challenge; the chip signs it with RSA.
 * This proves the chip is genuine (private key never leaves the chip).
 * With a CRQC: factor the public key from the chip → forge AA responses.
 * Key size: RSA-1024 is still found in passports issued before ~2015.
 */
int icao_active_authentication(const uint8_t *challenge, size_t challenge_len,
                               RSA *chip_private_key,           /* RSA-1024 or RSA-2048 */
                               uint8_t *response, size_t *response_len)
{
    unsigned int sig_len = RSA_size(chip_private_key);

    /*
     * RSA sign with PKCS#1 v1.5 + SHA-1 (older chips) or SHA-256 (newer chips).
     * The algorithm OID is in the chip's EF.DG15 (Active Authentication Info).
     * RSA-1024 is classically insecure since ~2010; RSA-2048 falls to Shor.
     */
    return RSA_sign(NID_sha256, challenge, challenge_len,
                    response, &sig_len, chip_private_key);
}

/*
 * Country Signing CA (CSCA) certificate distribution:
 *   - ICAO Public Key Directory (PKD) at pkd.icao.int
 *   - Contains RSA/ECDSA certificates for all 195 member states
 *   - These certs are downloaded by border control systems worldwide
 *   - A CRQC can recover any CSCA private key from its published certificate
 *   - Forged SODs from any country become indistinguishable from genuine ones
 *
 * Lifespan of issued passports: up to 10 years.
 * Chips cannot receive OTA updates — cryptography is burned at personalization.
 * Migration requires physical passport renewal for ~1.2 billion documents.
 */
