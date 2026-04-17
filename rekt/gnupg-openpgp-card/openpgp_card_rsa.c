/*
 * openpgp_card_rsa.c
 *
 * GnuPG smartcard daemon (scd) — RSA operations on OpenPGP smartcards.
 * Repository: git.gnupg.org
 * Source: https://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob;f=scd/app-openpgp.c
 *
 * The OpenPGP Card specification (OpenPGP Card v3.4) defines a smartcard
 * that stores up to three RSA keypairs:
 *   [1] Signature key (certifications + message signing)
 *   [2] Encryption key (PKCS#1 v1.5 / ECDH decryption)
 *   [3] Authentication key (SSH, system login)
 *
 * Physical cards implementing the OpenPGP Card spec:
 *   - YubiKey 5 series (OpenPGP applet, supports RSA-2048/4096 and ECC)
 *   - Nitrokey (OpenPGP 3, used heavily in German government and privacy-conscious orgs)
 *   - GNUK (free software token running on STM32)
 *   - Feitian ePass (widely deployed in Asia)
 *   - GnuPG's scd daemon talks to all of these via PCSC-Lite or built-in CCID
 *
 * RSA is the default key type for OpenPGP cards because:
 *   - OpenPGP Card spec v1.0 and v2.0 support only RSA (ECC added in v3.0, 2018)
 *   - Many deployed cards are v2.0 or v2.1 and cannot do ECC at all
 *   - GnuPG 2.1+ defaults to ECC for NEW keys but millions of existing cards have RSA
 *
 * There is NO PQC algorithm defined in the OpenPGP Card specification.
 * YubiKey's OpenPGP applet has no ML-DSA support.
 */

#include "scd.h"
#include "app-common.h"
#include "iso7816.h"

/* OpenPGP card key slot identifiers */
#define OPENPGP_KEY_SIGN    0x00B6   /* Signature key */
#define OPENPGP_KEY_ENCR    0x00B8   /* Encryption key */
#define OPENPGP_KEY_AUTH    0x00A4   /* Authentication key */

/*
 * do_sign() — perform an RSA signature operation on the OpenPGP card.
 * Source: scd/app-openpgp.c do_sign()
 *
 * Called by gpg-agent when GnuPG needs to sign data and the private key
 * is on an OpenPGP smartcard. The hash is sent to the card; the card
 * performs the RSA private key operation in hardware; the signature is returned.
 *
 * The private key NEVER leaves the card. The RSA public key, however, IS exported
 * and is stored in the keyring and uploaded to keyservers (hkps://keys.openpgp.org).
 * A CRQC derives the private key from the public key stored on keyservers.
 */
static gpg_error_t
do_sign(app_t app, ctrl_t ctrl, const char *keyidstr,
        int hashalgo,
        gpg_error_t (*pincb)(void *, const char *, char **), void *pincb_arg,
        const void *indata, size_t indatalen,
        unsigned char **outdata, size_t *outdatalen)
{
    gpg_error_t err;
    unsigned char data[35];     /* DigestInfo prefix + hash */
    unsigned char *response;
    size_t responselen;
    int exmode, le_value;

    /*
     * Build the DigestInfo structure for PKCS#1 v1.5 padding.
     * The card will prepend the RSA block structure and sign.
     *
     * For RSA-2048: the card computes hash ^ d mod n internally.
     * The key 'd' (private exponent) never leaves the card's secure element.
     * The key 'n' (modulus, 256 bytes for RSA-2048) is in the public key,
     * uploaded to keyservers and stored in ~/.gnupg/pubring.kbx.
     */
    if (hashalgo == GCRY_MD_SHA256) {
        /* SHA-256 DigestInfo prefix (RFC 3447 Section 9.2) */
        memcpy(data, "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04"
                     "\x02\x01\x05\x00\x04\x20", 19);
        memcpy(data + 19, indata, 32);   /* SHA-256 hash (32 bytes) */
        indatalen = 51;
    } else if (hashalgo == GCRY_MD_SHA1) {
        /* SHA-1 prefix — still used in many deployed GnuPG configs */
        memcpy(data, "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00"
                     "\x04\x14", 15);
        memcpy(data + 15, indata, 20);
        indatalen = 35;
    }

    /* Select the signature key slot (DO 0x00B6) */
    err = iso7816_select_data(app->slot, 0, OPENPGP_KEY_SIGN);
    if (err) return err;

    /* Send COMPUTE DIGITAL SIGNATURE command to the card */
    /* The card applies RSA private key operation internally */
    /* Response is 256 bytes (RSA-2048) or 512 bytes (RSA-4096) */
    err = iso7816_compute_ds(app->slot, exmode, data, indatalen, le_value,
                              &response, &responselen);
    if (err) return err;

    *outdata = response;
    *outdatalen = responselen;
    return 0;
}

/*
 * do_decipher() — RSA decryption on the OpenPGP card.
 * Source: scd/app-openpgp.c do_decipher()
 *
 * Called when gpg decrypts an encrypted file or email. The symmetric session
 * key (encrypted with the card's RSA public key) is sent to the card;
 * the card decrypts it using its RSA private key.
 *
 * This is the exact operation for HNDL: intercept encrypted emails/files,
 * store them. Later, when a CRQC derives the RSA private key from the public
 * key on the keyserver, decrypt all stored ciphertext.
 */
static gpg_error_t
do_decipher(app_t app, ctrl_t ctrl, const char *keyidstr,
            gpg_error_t (*pincb)(void *, const char *, char **), void *pincb_arg,
            const void *indata, size_t indatalen,
            unsigned char **outdata, size_t *outdatalen,
            unsigned int *r_info)
{
    /* indata: RSA-encrypted session key (256 bytes for RSA-2048) */
    /* The card decrypts using its internal RSA-2048 private key */
    return iso7816_decipher(app->slot, 0, indata, indatalen,
                             0,     /* le value */
                             0xA6,  /* Padding indicator: PKCS#1 */
                             outdata, outdatalen);
}

/*
 * app_openpgp_getattr() — exports the card's RSA public key.
 * Source: scd/app-openpgp.c do_getattr() / retrieve_key_material()
 *
 * This exports the RSA-2048 public key from the card. GnuPG uploads it to
 * keyservers (hkps://keys.openpgp.org, hkps://keyserver.ubuntu.com).
 * The public key is the CRQC input.
 *
 * Key attributes data object (DO 00C1/00C2/00C3) returns:
 *   key_attr->algo  = 0x01       (RSA)
 *   key_attr->nbits = 2048       (or 4096)
 *   key_attr->e     = 65537
 *
 * The modulus 'n' and exponent 'e' are exported via:
 *   iso7816_get_data(slot, 0, 0x7F49, ...)  -- public key template
 */
gpg_error_t
app_openpgp_getattr(app_t app, ctrl_t ctrl, const char *name)
{
    struct key_attr attr;

    /* Retrieve RSA key attributes for each key slot */
    /* Returns RSA key size (2048, 3072, 4096) and key material */

    /* For the signature key: */
    get_one_do(app, 0x00C1, &attr);  /* DO 00C1 = sig key attributes */
    /* attr.nbits = 2048 (or 4096) */
    /* attr.algo  = 0x01 = RSA     */

    /* Export public key modulus n and exponent e */
    return retrieve_key_material(app, ctrl, 0xB6 /* sig key */);
}
