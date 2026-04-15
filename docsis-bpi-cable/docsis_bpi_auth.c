/*
 * docsis_bpi_auth.c
 *
 * DOCSIS BPI+ (Baseline Privacy Interface Plus) — cable modem authentication.
 * Sources:
 *   - CableLabs CM-SP-SECv3.1-I11-200408 (DOCSIS 3.1 Security Specification)
 *   - CableLabs CM-SP-SECv4.0-I04-240510 (DOCSIS 4.0 Security Specification)
 *   - ANSI/SCTE 55-1, 55-2 (legacy BPI)
 *   - CableLabs Certificate Policy Statement (DOCSIS Root CA)
 *
 * Every cable modem has a factory-programmed X.509 certificate containing
 * an RSA-1024 (DOCSIS 3.0) or RSA-2048 (DOCSIS 3.1+) public key. The cert
 * chains:  DOCSIS Root CA -> Manufacturer CA -> Device Certificate.
 *
 * Authentication flow (BPKM = Baseline Privacy Key Management):
 *
 *   CM                                    CMTS
 *   --                                    ----
 *   BPKM Auth Request (cert, cap)  -->
 *                                    <--  BPKM Auth Reply (RSA-encrypted AK)
 *   BPKM TEK Request               -->
 *                                    <--  BPKM TEK Reply (AES-wrapped TEKs)
 *   AES-128 traffic encryption    <-->
 *
 * AK = 160-bit Authorization Key
 * TEK = 128-bit Traffic Encryption Key (one per SAID, rotated every ~12h)
 * Both are ultimately protected by the RSA-wrapped AK.
 */

#include <stdint.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>

#define BPI_AK_LEN              20    /* 160-bit Authorization Key */
#define BPI_TEK_LEN             16    /* 128-bit Traffic Encryption Key */
#define BPI_KEK_LEN             8     /* Key Encryption Key (legacy, 3DES) */
#define BPI_SAID_LEN            2     /* Security Association ID */

/*
 * CableLabs DOCSIS Root CA certificate (hardcoded into every CMTS).
 * The actual cert is published by CableLabs; modulus is ~2048 bits.
 */
static const uint8_t CABLELABS_DOCSIS_ROOT_CERT_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "/* CableLabs DOCSIS Root CA — published in PKI-SP-CABLELABS-DIGICERT-TRUST */\n"
    "-----END CERTIFICATE-----\n";

/*
 * docsis_verify_device_cert — CMTS-side verification of a cable modem's
 * device certificate chain. Called on every CM registration.
 */
int
docsis_verify_device_cert(X509 *cm_device_cert,
                           STACK_OF(X509) *cm_chain,
                           X509_STORE *cablelabs_root_store)
{
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (!ctx) return -1;

    X509_STORE_CTX_init(ctx, cablelabs_root_store, cm_device_cert, cm_chain);

    /* DOCSIS-specific: the cert must contain the CM's MAC address in the
     * subject CN as "MAC:xx:xx:xx:xx:xx:xx" — CMTS cross-checks this
     * against the MAC in the BPKM Auth Request header. */

    int result = X509_verify_cert(ctx);
    X509_STORE_CTX_free(ctx);
    return result;
}

/*
 * docsis_encrypt_ak — CMTS-side wrap of Authorization Key to cable modem
 * using RSA-PKCS1-v1_5 (BPI+ spec requires this; RSA-OAEP optional in
 * DOCSIS 4.0 but rarely deployed).
 *
 * The CM's RSA public key is extracted from its device certificate.
 */
int
docsis_encrypt_ak(X509 *cm_device_cert,
                   const uint8_t ak[BPI_AK_LEN],
                   uint8_t *encrypted_ak,
                   size_t *encrypted_ak_len)
{
    EVP_PKEY *pubkey = X509_get_pubkey(cm_device_cert);
    RSA *rsa_pub = EVP_PKEY_get1_RSA(pubkey);

    int rsa_size = RSA_size(rsa_pub);  /* 128 or 256 bytes */
    int result = RSA_public_encrypt(BPI_AK_LEN, ak,
                                     encrypted_ak, rsa_pub,
                                     RSA_PKCS1_PADDING);
    *encrypted_ak_len = (result > 0) ? result : 0;

    RSA_free(rsa_pub);
    EVP_PKEY_free(pubkey);
    return (result > 0) ? 0 : -1;
}

/*
 * docsis_decrypt_ak — modem-side unwrap of AK using its factory-burned
 * RSA private key. On DOCSIS 3.0 modems this is RSA-1024; on 3.1+ it
 * is RSA-2048.
 */
int
docsis_decrypt_ak(RSA *cm_rsa_private,
                   const uint8_t *encrypted_ak, size_t encrypted_ak_len,
                   uint8_t ak[BPI_AK_LEN])
{
    uint8_t buf[256];
    int result = RSA_private_decrypt(encrypted_ak_len, encrypted_ak,
                                      buf, cm_rsa_private,
                                      RSA_PKCS1_PADDING);
    if (result != BPI_AK_LEN) return -1;
    memcpy(ak, buf, BPI_AK_LEN);
    return 0;
}

/*
 * docsis_derive_tek — derive a Traffic Encryption Key from the AK using
 * HMAC-SHA-1 as a PRF (legacy BPI+), or HMAC-SHA-256 on DOCSIS 4.0.
 */
void
docsis_derive_tek(const uint8_t ak[BPI_AK_LEN],
                   const uint8_t said[BPI_SAID_LEN],
                   uint8_t tek[BPI_TEK_LEN])
{
    uint8_t prf_out[20];
    uint32_t prf_len = sizeof(prf_out);
    HMAC(EVP_sha1(), ak, BPI_AK_LEN,
         said, BPI_SAID_LEN,
         prf_out, &prf_len);
    memcpy(tek, prf_out, BPI_TEK_LEN);
}

/*
 * Attack scenario:
 *
 *  1. Obtain the CableLabs DOCSIS Root CA certificate (it's published —
 *     CableLabs distributes it for CMTS vendors). Factor the RSA key.
 *
 *  2. Forge a manufacturer sub-CA certificate under the DOCSIS Root.
 *     Under this, mint device certificates with any MAC / any modem identity.
 *
 *  3. Present the forged device cert to a target CMTS during BPKM
 *     Auth Request. CMTS verifies the (forged) chain against the
 *     (compromised-but-still-trusted) DOCSIS Root; verification passes.
 *
 *  4. CMTS encrypts the AK to the modem's (attacker-held) RSA public key.
 *     Attacker decrypts, derives TEKs, and can now send/receive DOCSIS
 *     MAC-layer traffic as the spoofed modem. Free cable internet on any
 *     provisioning tier, including business-class symmetric uploads.
 *
 *  5. For passive eavesdropping: factor the VICTIM modem's RSA public key
 *     (recoverable from any BPKM Auth Request — these are not encrypted in
 *     transit on the pre-auth DOCSIS management path). With the modem's
 *     RSA private key, decrypt any archived CMTS traffic targeted to that
 *     modem's AK. Historical cable broadband traffic falls open.
 */
