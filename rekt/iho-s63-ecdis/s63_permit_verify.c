/*
 * s63_permit_verify.c
 *
 * IHO S-63 Data Protection Scheme — permit verification for ENC cells.
 * Sources:
 *   - IHO S-63 Edition 1.2.0 (January 2015)
 *   - IHO S-63 Annex B (certificate format and signature algorithms)
 *   - IMO SOLAS V/19 (ECDIS carriage requirement)
 *   - IEC 61174 (ECDIS performance standard, references S-63)
 *
 * The trust anchor is the IHB (International Hydrographic Bureau) RSA key.
 * Its public key is distributed as IHO.CRT — installed on every ECDIS
 * during manufacture or commissioning. S-63 originally specified RSA-1024;
 * Edition 1.2 permits RSA up to 2048 but the scheme administrator root
 * remains RSA-1024 across the installed base.
 *
 * Chart encryption:
 *   - Cell key = 40-bit hex (originally for Blowfish in S-63 Ed 1.0;
 *     migrated to AES in Ed 1.2)
 *   - Cell is encrypted with the cell key, distributed with .ENC suffix
 *   - Cell key delivered in PERMIT.TXT, one line per cell, encrypted
 *     with the ECDIS's "HW_ID" and signed by the Data Server
 *
 * An attacker who factors the IHB RSA-1024 key can issue a rogue
 * "Data Server Certificate" accepted by every ECDIS worldwide, then sign
 * forged permits for forged chart cells.
 */

#include <stdint.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/aes.h>

/* S-63 Data Server Certificate (simplified — real format is ASN.1-like
 * but S-63-specific, not PKCS). */
struct s63_ds_cert {
    char     data_server_name[32];   /* e.g., "UKHO", "NOAA", "Primar" */
    uint8_t  ds_rsa_modulus[256];    /* RSA-2048 public key modulus */
    uint8_t  ds_rsa_exponent[4];     /* usually 65537 */
    uint32_t valid_from;             /* YYYYMMDD packed */
    uint32_t valid_until;
    uint8_t  ihb_signature[128];     /* RSA-1024 signature by IHB root */
};

/* S-63 cell permit — one per ENC cell, per ECDIS installation. */
struct s63_permit {
    char     cell_name[16];          /* e.g., "GB5X01SE" */
    uint32_t edition;                /* edition number of the cell */
    uint8_t  encrypted_cell_key[16]; /* cell AES key, encrypted with HW_ID */
    uint8_t  ds_signature[256];      /* RSA-2048 signature by data server */
    uint8_t  ds_cert_index[4];       /* reference to DS cert used */
};

/*
 * s63_verify_data_server_cert — verify a Data Server Certificate was signed
 * by the IHB scheme administrator. The IHB public key comes from IHO.CRT
 * shipped with the ECDIS.
 */
int
s63_verify_data_server_cert(const struct s63_ds_cert *cert,
                             RSA *ihb_pubkey)
{
    /* Canonical encoding of cert fields for signature: concat of
     * data_server_name || ds_rsa_modulus || ds_rsa_exponent ||
     * valid_from || valid_until. SHA-1 in S-63 Ed 1.1,
     * SHA-256 in Ed 1.2. */
    uint8_t to_sign[32 + 256 + 4 + 4 + 4];
    uint8_t *p = to_sign;
    memcpy(p, cert->data_server_name, 32); p += 32;
    memcpy(p, cert->ds_rsa_modulus, 256); p += 256;
    memcpy(p, cert->ds_rsa_exponent, 4); p += 4;
    memcpy(p, &cert->valid_from, 4); p += 4;
    memcpy(p, &cert->valid_until, 4);

    uint8_t digest[32];
    SHA256(to_sign, sizeof(to_sign), digest);

    /* IHB signature: RSA-1024 PKCS#1 v1.5 over SHA-256 digest. */
    return RSA_verify(NID_sha256,
                      digest, sizeof(digest),
                      cert->ihb_signature, 128,
                      ihb_pubkey);
}

/*
 * s63_verify_permit — verify a cell permit was signed by the data server.
 * Caller must have already verified the DS cert against the IHB root.
 */
int
s63_verify_permit(const struct s63_permit *permit,
                   const struct s63_ds_cert *ds_cert)
{
    /* Reconstruct data server public key from cert */
    RSA *ds_key = RSA_new();
    BIGNUM *n = BN_bin2bn(ds_cert->ds_rsa_modulus, 256, NULL);
    BIGNUM *e = BN_bin2bn(ds_cert->ds_rsa_exponent, 4, NULL);
    RSA_set0_key(ds_key, n, e, NULL);

    uint8_t to_sign[16 + 4 + 16];
    memcpy(to_sign, permit->cell_name, 16);
    memcpy(to_sign + 16, &permit->edition, 4);
    memcpy(to_sign + 20, permit->encrypted_cell_key, 16);

    uint8_t digest[32];
    SHA256(to_sign, sizeof(to_sign), digest);

    int ok = RSA_verify(NID_sha256, digest, sizeof(digest),
                        permit->ds_signature, 256, ds_key);
    RSA_free(ds_key);
    return ok;
}

/*
 * s63_decrypt_cell — decrypt ENC cell data using the permit-delivered cell key.
 * The HW_ID unwrapping of encrypted_cell_key is omitted here; real ECDIS
 * derives an AES key from the HW_ID and uses it to unwrap the cell key.
 *
 * An attacker with forged IHB-signed DS cert + forged permit can feed any
 * cell content they want into the ECDIS chart display.
 */
int
s63_decrypt_cell(const uint8_t *enc_cell, size_t len,
                  const uint8_t cell_key[16],
                  uint8_t *out)
{
    AES_KEY key;
    AES_set_decrypt_key(cell_key, 128, &key);
    for (size_t i = 0; i < len; i += 16) {
        AES_decrypt(enc_cell + i, out + i, &key);
    }
    return 0;
}

/*
 * Attack scenario:
 *   1. Obtain IHO.CRT from any ECDIS install (readable file on every
 *      commercial marine install — no credentials needed on the bridge PC,
 *      often just a shared Windows machine).
 *   2. Factor the IHB RSA-1024 modulus (offline, classical).
 *   3. Forge a Data Server Certificate with attacker-controlled RSA key
 *      and a plausible data server name ("Primar", "NOAA", etc.).
 *   4. Sign forged permits for forged cell content — shifted depth contours,
 *      deleted wrecks, phantom shoals, erroneous traffic separation zones.
 *   5. Deliver update via the ship's normal chart distribution channel
 *      (satellite email pull, port USB stick, agent delivery).
 *   6. Bridge watch installs update; ECDIS displays forged chart; autopilot
 *      follows the forged chart into whatever terrain the attacker chose.
 */
