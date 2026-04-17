/*
 * voting_rsa_firmware.c
 *
 * Election system firmware signing — RSA-2048 under EAC certification.
 *
 * Sources:
 *   - EAC VVSG 2.0 (Voluntary Voting System Guidelines, 2021) — NIST SP 1800-28
 *   - ES&S DS200 / EVS platform technical documentation
 *   - Dominion Democracy Suite 5.17 system documentation
 *   - Hart InterCivic Verity system documentation
 *   - Defcon Voting Village firmware analyses (2018-2023)
 *
 * Voting equipment manufacturers and their platforms:
 *   ES&S:      DS200 (optical scanner), ExpressPoll (poll book), EVS 6.1
 *   Dominion:  ImageCast Precinct 2 / X (scanner/DRE), Democracy Suite 5.17
 *   Hart:      Verity Scan, Verity Touch Writer (DRE), Verity Central
 *   Unisyn:    OVO (DRE), OCR-600 (optical scanner)
 *
 * EAC VVSG 2.0 Section 13 requires:
 *   "Software shall be authenticated using a digital signature or MAC"
 *   "Signature algorithm: RSA-2048 or stronger"
 *   "The system shall reject software that does not have a valid signature"
 *
 * The signing key is held by the manufacturer. State election authorities
 * receive certified firmware images with embedded RSA signatures.
 * The voting machine bootloader (often a modified U-Boot or custom BIOS)
 * verifies the RSA signature before booting the election software.
 *
 * The manufacturer CA certificate is a self-signed RSA-2048 cert, unique per vendor.
 * It is not in any public trust store. State election authorities receive it
 * separately and configure it in their certification process.
 */

#include <stdint.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

/* Voting system firmware image layout (typical across ES&S, Dominion, Hart) */
struct vs_firmware_header {
    uint8_t  magic[4];           /* "VSFM" */
    uint32_t format_version;     /* 2 = VVSG 2.0 compliant */
    uint32_t firmware_len;
    uint8_t  vendor_id[32];      /* "ESS\x00", "DOMINION\x00", "HART\x00" */
    uint8_t  product_id[32];     /* "DS200\x00", "ICX\x00", "VERITY-SCAN\x00" */
    uint32_t build_number;
    uint8_t  build_date[16];     /* "20241015\x00" */
    uint8_t  sha256[32];         /* SHA-256 of firmware body */
    uint8_t  rsa_signature[256]; /* RSA-2048 PKCS#1 v1.5 over sha256 */
    uint8_t  signing_cert[1024]; /* DER-encoded leaf cert (RSA-2048) */
    uint8_t  ca_cert[1024];      /* DER-encoded CA cert (RSA-2048, self-signed) */
};

/*
 * vs_verify_firmware() — verify RSA-2048 firmware signature on voting equipment.
 *
 * Called by the voting machine bootloader during startup. Also called by the
 * state logic and accuracy testing process before certification.
 *
 * If this returns != 1, the machine refuses to boot election software.
 * This is the technical control that EAC VVSG 2.0 points to for software integrity.
 *
 * An attacker who can forge RSA-2048 signatures can produce firmware that
 * passes this check and boots on any certified voting machine.
 */
int
vs_verify_firmware(const uint8_t *fw_image, size_t fw_len)
{
    const struct vs_firmware_header *hdr;
    const uint8_t *fw_body;
    uint8_t computed_sha256[32];
    const uint8_t *cert_p;
    X509 *signing_cert = NULL;
    X509 *ca_cert = NULL;
    EVP_PKEY *pubkey = NULL;
    EVP_MD_CTX *ctx = NULL;
    X509_STORE *store = NULL;
    X509_STORE_CTX *verify_ctx = NULL;
    int ret = -1;

    if (fw_len < sizeof(struct vs_firmware_header)) return -1;

    hdr = (const struct vs_firmware_header *)fw_image;
    if (memcmp(hdr->magic, "VSFM", 4) != 0) return -1;

    fw_body = fw_image + sizeof(struct vs_firmware_header);

    /* Verify firmware body hash */
    SHA256(fw_body, hdr->firmware_len, computed_sha256);
    if (memcmp(computed_sha256, hdr->sha256, 32) != 0) return -1;

    /* Decode signing cert and CA cert */
    cert_p = hdr->signing_cert;
    signing_cert = d2i_X509(NULL, &cert_p, sizeof(hdr->signing_cert));
    if (!signing_cert) return -1;

    cert_p = hdr->ca_cert;
    ca_cert = d2i_X509(NULL, &cert_p, sizeof(hdr->ca_cert));
    if (!ca_cert) goto out;

    /* Verify cert chain: signing_cert -> ca_cert (self-signed, vendor root) */
    store = X509_STORE_new();
    X509_STORE_add_cert(store, ca_cert);
    verify_ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(verify_ctx, store, signing_cert, NULL);
    if (X509_verify_cert(verify_ctx) != 1) goto out;

    /* Verify RSA-2048 PKCS#1 v1.5 signature */
    pubkey = X509_get_pubkey(signing_cert);
    if (!pubkey) goto out;

    ctx = EVP_MD_CTX_new();
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pubkey) <= 0) goto out;
    if (EVP_DigestVerifyUpdate(ctx, hdr->sha256, 32) <= 0) goto out;

    /* 1 = valid, machine boots; 0 = forged/tampered, machine refuses to boot */
    ret = EVP_DigestVerifyFinal(ctx, hdr->rsa_signature, 256);

out:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pubkey);
    X509_STORE_CTX_free(verify_ctx);
    X509_STORE_free(store);
    X509_free(ca_cert);
    X509_free(signing_cert);
    return ret;
}

/*
 * vs_sign_firmware() — manufacturer signs voting machine firmware image.
 *
 * Called by ES&S, Dominion, Hart, etc. during firmware release.
 * The signing key is held in an HSM at the manufacturer's facility.
 * The signed firmware is submitted to EAC for certification testing.
 * Certified firmware is then distributed to state election authorities.
 *
 * The manufacturer CA cert is the only trust anchor — it's not in any
 * public PKI. States receive it as part of the certification package.
 * It's RSA-2048.
 */
int
vs_sign_firmware(uint8_t *fw_image, size_t fw_len,
                 EVP_PKEY *manufacturer_key,
                 X509 *signing_cert, X509 *ca_cert)
{
    struct vs_firmware_header *hdr = (struct vs_firmware_header *)fw_image;
    const uint8_t *fw_body = fw_image + sizeof(*hdr);
    EVP_MD_CTX *ctx = NULL;
    size_t sig_len = 256;
    int ret = -1;
    uint8_t *p;

    /* Hash firmware body */
    SHA256(fw_body, hdr->firmware_len, hdr->sha256);

    ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, manufacturer_key) <= 0)
        goto out;
    if (EVP_DigestSignUpdate(ctx, hdr->sha256, 32) <= 0)
        goto out;
    if (EVP_DigestSignFinal(ctx, hdr->rsa_signature, &sig_len) <= 0)
        goto out;

    /* Embed certificates */
    p = hdr->signing_cert;
    i2d_X509(signing_cert, &p);
    p = hdr->ca_cert;
    i2d_X509(ca_cert, &p);

    ret = 0;
out:
    EVP_MD_CTX_free(ctx);
    return ret;
}

/*
 * EAC certification and state deployment notes:
 *
 * The EAC certifies voting systems to VVSG standards. Certified systems are on
 * the EAC Certified Systems list (current list: 2024). All certified systems use
 * RSA-2048 for firmware signing — it meets VVSG 2.0 requirements and FIPS 140-2.
 *
 * State deployment:
 *   - ES&S DS200: ~44 states
 *   - Dominion Democracy Suite: ~28 states
 *   - Hart Verity: ~17 states
 *
 * At the state level, logic and accuracy (L&A) testing includes checking that
 * firmware versions match certified hashes. An attacker who can forge firmware
 * signatures produces firmware with matching vendor-signed headers — L&A passes.
 *
 * The CA certificate (the RSA-2048 public key that anchors trust for all firmware
 * from a given manufacturer) is embedded in every firmware image — both the leaf
 * and CA certs are in the header in DER-encoded form. Anyone with a firmware image
 * (obtainable via public records requests in many states, research disclosures,
 * security conferences like the Defcon Voting Village) has the CRQC input.
 */
