/*
 * nuclear_rsa_sign.c
 *
 * Nuclear I&C firmware signing — RSA-2048 under IEC 62645 / IEC 62443.
 * This covers software authentication for safety-critical nuclear instrumentation
 * and control systems: reactor protection, engineered safety features, plant control.
 *
 * Sources:
 *   - IEC 62645:2014 "Nuclear power plants — Instrumentation and control systems —
 *     Requirements for security programmes for computer-based systems"
 *   - IAEA NSS No. 17 "Computer Security at Nuclear Facilities"
 *   - NRC Regulatory Guide 5.71 "Cyber Security Programs for Nuclear Facilities"
 *   - Invensys Foxboro / Siemens SPPA-T3000 / Emerson Ovation I&C platform docs
 *   - IEEE 603-2018 (nuclear safety system software requirements)
 *
 * Nuclear I&C software signing applies to:
 *   - Reactor Protection System (RPS) — SCRAM logic
 *   - Engineered Safety Feature Actuation System (ESFAS) — ECCS, containment isolation
 *   - Neutron flux monitoring
 *   - Coolant flow, pressure, and temperature instrumentation
 *   - Plant control system (non-safety but still regulated)
 *
 * The code signing CA is typically the I&C platform vendor's private PKI.
 * For SPPA-T3000 (Siemens): internal Siemens Nuclear I&C CA, RSA-2048.
 * For Ovation (Emerson): internal Emerson I&C CA, RSA-2048.
 *
 * NRC RG 5.71 requires "integrity verification" for safety I&C software.
 * In practice this means the firmware/software update must carry a valid
 * RSA-2048 signature from the vendor CA before the I&C controller will apply it.
 */

#include <stdint.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

/* Nuclear I&C firmware image header */
struct nic_fw_header {
    uint32_t magic;              /* 0x4E494346 = "NICF" */
    uint32_t version;
    uint32_t image_len;
    uint8_t  platform_id[16];   /* e.g., "SPPA-T3000\x00..." */
    uint8_t  safety_class;      /* 1 = Safety Class 1 (RPS/ESFAS), 2 = SC-2, 3 = SC-3 */
    uint8_t  reserved[3];
    uint8_t  sha256_digest[32]; /* SHA-256 of firmware body */
    uint8_t  signature[256];    /* RSA-2048 PKCS#1 v1.5 signature over sha256_digest */
    uint8_t  cert_der[1024];    /* Signing certificate (vendor I&C CA signed, RSA-2048) */
};

/*
 * nic_verify_firmware() — verify RSA-2048 signature on nuclear I&C firmware image.
 *
 * Called by the I&C controller bootloader before applying any firmware update.
 * The vendor CA certificate is burned into the controller's tamper-resistant flash.
 * The firmware signature must chain back to the vendor CA.
 *
 * For safety-class firmware (RPS, ESFAS): this check must pass or the update
 * is rejected. The controller stays on old firmware. This is the mechanism
 * that prevents unauthorized modification of nuclear safety software.
 *
 * An attacker who can forge RSA-2048 signatures can load arbitrary firmware
 * onto nuclear I&C controllers, including safety-class ones.
 */
int
nic_verify_firmware(const uint8_t *fw_image, size_t fw_len,
                    X509 *vendor_ca_cert)
{
    const struct nic_fw_header *hdr;
    const uint8_t *fw_body;
    size_t fw_body_len;
    uint8_t computed_digest[32];
    EVP_PKEY *signing_key = NULL;
    X509 *signing_cert = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    X509_STORE *store = NULL;
    X509_STORE_CTX *verify_ctx = NULL;
    const uint8_t *cert_p;
    int ret = -1;

    if (fw_len < sizeof(struct nic_fw_header)) return -1;

    hdr = (const struct nic_fw_header *)fw_image;
    if (hdr->magic != 0x4E494346) return -1;  /* bad magic */

    fw_body = fw_image + sizeof(struct nic_fw_header);
    fw_body_len = hdr->image_len;

    if (fw_body + fw_body_len > fw_image + fw_len) return -1;

    /* Step 1: verify SHA-256 of firmware body */
    SHA256(fw_body, fw_body_len, computed_digest);
    if (memcmp(computed_digest, hdr->sha256_digest, 32) != 0) {
        /* firmware body is corrupted or tampered */
        return -1;
    }

    /* Step 2: decode the signing certificate from the firmware header */
    cert_p = hdr->cert_der;
    signing_cert = d2i_X509(NULL, &cert_p, sizeof(hdr->cert_der));
    if (!signing_cert) return -1;

    /* Step 3: verify signing cert chains to vendor CA */
    store = X509_STORE_new();
    if (!store) goto out;
    X509_STORE_add_cert(store, vendor_ca_cert);

    verify_ctx = X509_STORE_CTX_new();
    if (!verify_ctx) goto out;
    X509_STORE_CTX_init(verify_ctx, store, signing_cert, NULL);

    if (X509_verify_cert(verify_ctx) != 1) {
        /* signing cert doesn't chain to vendor CA — reject firmware */
        goto out;
    }

    /* Step 4: verify RSA-2048 signature over SHA-256 digest */
    signing_key = X509_get_pubkey(signing_cert);
    if (!signing_key) goto out;

    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) goto out;

    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, signing_key) <= 0)
        goto out;
    if (EVP_DigestVerifyUpdate(md_ctx, hdr->sha256_digest, 32) <= 0)
        goto out;

    /* This is the RSA-2048 PKCS#1 v1.5 verify — the only thing standing between
     * "authorized vendor firmware" and "whatever you want to run on a nuclear
     * safety controller" */
    ret = EVP_DigestVerifyFinal(md_ctx, hdr->signature, sizeof(hdr->signature));
    /* 1 = valid, 0 = invalid, < 0 = error */

out:
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(signing_key);
    X509_STORE_CTX_free(verify_ctx);
    X509_STORE_free(store);
    X509_free(signing_cert);
    return ret;
}

/*
 * nic_sign_firmware() — sign nuclear I&C firmware image (vendor PKI operation).
 *
 * Called by the I&C platform vendor during firmware release. The signing key
 * is stored in an HSM (Thales Luna or Utimaco) at the vendor's secure facility.
 * The resulting signature is embedded in the firmware image header.
 *
 * The vendor CA certificate is RSA-2048. The leaf signing certificate is RSA-2048.
 * No PQC option exists in any current I&C platform (SPPA-T3000, Ovation, Tricon).
 */
int
nic_sign_firmware(uint8_t *fw_image, size_t fw_len,
                  EVP_PKEY *vendor_signing_key,
                  X509 *vendor_signing_cert)
{
    struct nic_fw_header *hdr = (struct nic_fw_header *)fw_image;
    const uint8_t *fw_body = fw_image + sizeof(struct nic_fw_header);
    EVP_MD_CTX *md_ctx = NULL;
    size_t sig_len = 256;
    int ret = -1;

    /* Compute SHA-256 of firmware body */
    SHA256(fw_body, hdr->image_len, hdr->sha256_digest);

    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) return -1;

    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, vendor_signing_key) <= 0)
        goto out;
    if (EVP_DigestSignUpdate(md_ctx, hdr->sha256_digest, 32) <= 0)
        goto out;

    /* RSA-2048 PKCS#1 v1.5 sign — output is 256 bytes */
    if (EVP_DigestSignFinal(md_ctx, hdr->signature, &sig_len) <= 0)
        goto out;

    /* Embed the signing certificate */
    {
        uint8_t *cert_p = hdr->cert_der;
        int cert_len = i2d_X509(vendor_signing_cert, &cert_p);
        if (cert_len <= 0) goto out;
    }

    ret = 0;
out:
    EVP_MD_CTX_free(md_ctx);
    return ret;
}

/*
 * IEC 62645 / NRC RG 5.71 context:
 *
 * IEC 62645 requires "measures to protect against the introduction of unauthorized
 * software modifications." In practice, reactor protection and ESFAS controllers
 * enforce this via RSA code signing.
 *
 * Tricon (Triconex / Schneider Electric) — used as SIS at petrochemical plants and
 * at the Saudi Aramco TRISIS/TRITON attack (2017). TRISIS targeted the safety
 * instrumented system by bypassing Triconex firmware authentication. Current
 * Tricon v11 firmware signing uses RSA-2048.
 *
 * SPPA-T3000 (Siemens) — I&C platform for ~170 nuclear units worldwide including
 * German, French, and South Korean reactors. Firmware signing: RSA-2048.
 *
 * Ovation (Emerson) — reactor control at US and European nuclear plants. RSA-2048.
 *
 * An attacker with a CRQC and a copy of any vendor's I&C firmware update (obtainable
 * via regulatory filings, vendor disclosures, or network capture) can derive the
 * vendor's signing key from the certificate embedded in the firmware image, then
 * sign arbitrary replacement firmware for nuclear safety controllers.
 *
 * This is exactly what TRISIS did, but required finding Triconex zero-days.
 * With RSA broken, you need: the vendor certificate (public, in every firmware image)
 * and a CRQC. The zero-days become optional.
 */
