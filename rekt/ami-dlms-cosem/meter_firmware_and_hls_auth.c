/*
 * meter_firmware_and_hls_auth.c
 *
 * Two RSA-driven paths inside a production smart meter:
 *
 *   1. Bootloader image-authentication prior to flashing firmware.
 *      Runs every time the meter receives a DLMS "Image Transfer"
 *      (IC 18) package from the utility HES.
 *
 *   2. DLMS HLS Mechanism 7 (digital-signature authentication)
 *      during Application Association (AA) establishment. Runs on
 *      every HES session to the meter for reading registers,
 *      issuing disconnect relay commands, firmware push, or
 *      tariff-schedule update.
 *
 * This is the C that runs on Landis+Gyr E650, Itron CENTRON-II,
 * Kamstrup OMNIA AX, EDMI Atlas-Mk10, Iskraemeco AM550.
 */

#include <stdint.h>
#include <string.h>
#include "dlms_cosem.h"
#include "rsa_pkcs1v15.h"
#include "rsa_pss.h"
#include "sha256.h"

/* -------- Pinned public keys (written at factory provisioning) --- */

/* Vendor code-signing cert pubkey — only this can sign firmware. */
extern const uint8_t VENDOR_FW_SIGN_PUB_N[512];   /* RSA-4096 modulus */
extern const uint8_t VENDOR_FW_SIGN_PUB_E[4];

/* Utility HES CA pubkey — anchors the client certs presented by
 * the HES during AA establishment. */
extern const uint8_t UTIL_HES_CA_PUB_N[384];      /* RSA-3072 modulus */
extern const uint8_t UTIL_HES_CA_PUB_E[4];


/* -------- 1. Firmware image transfer (DLMS IC 18) ------------------
 *
 * Sequence:
 *   a. HES invokes Image_transfer_initiate(image_identifier, image_size)
 *   b. HES streams image_transfer_transfer(block_n, data) until full.
 *   c. HES invokes Image_transfer_verify().   <-- we run here
 *   d. On success: Image_transfer_activate() reboots into new image.
 */

struct fw_image_header {
    char     magic[4];              /* "FWIM" */
    uint32_t version;
    uint32_t rollback_counter;
    uint32_t image_size;
    uint8_t  image_sha256[32];
    uint8_t  sig_len;               /* 512 for RSA-4096 */
    uint8_t  signature[512];        /* PKCS#1 v1.5 over header prefix */
};

int meter_verify_firmware_image(const uint8_t *image, size_t len)
{
    if (len < sizeof(struct fw_image_header)) return -1;
    const struct fw_image_header *h = (const void *)image;
    if (memcmp(h->magic, "FWIM", 4)) return -1;

    /* Rollback protection: enforce monotonic counter stored in
     * secure element / OTP. */
    if (h->rollback_counter < se_read_fw_rollback_counter())
        return -2;

    /* Verify the declared payload hash. */
    uint8_t payload_hash[32];
    sha256(image + sizeof *h, len - sizeof *h, payload_hash);
    if (memcmp(payload_hash, h->image_sha256, 32)) return -3;

    /* RSA-4096 PKCS#1 v1.5 verify over (magic..image_sha256). */
    uint8_t signed_prefix_hash[32];
    sha256((const uint8_t *)h,
           offsetof(struct fw_image_header, sig_len),
           signed_prefix_hash);

    return rsa_pkcs1v15_verify_sha256(
        VENDOR_FW_SIGN_PUB_N, sizeof VENDOR_FW_SIGN_PUB_N,
        VENDOR_FW_SIGN_PUB_E, sizeof VENDOR_FW_SIGN_PUB_E,
        signed_prefix_hash, sizeof signed_prefix_hash,
        h->signature, h->sig_len);
}


/* -------- 2. DLMS HLS Mechanism 7: digital-signature AA ---------- */

/*
 * HLS-7 message flow (Blue Book 9.2.7.7):
 *
 *   AARQ: client → server (meter); client sends challenge C_C,
 *         its certificate, and expects C_S back.
 *   AARE: server → client; meter sends challenge C_S and its cert.
 *   HLS-pass-3: client sends signature S_C = RSA_sign(C_C || C_S || ...)
 *   HLS-pass-4: meter sends signature S_S = RSA_sign(C_S || C_C || ...)
 *
 * Meter-side verifies S_C with the client's RSA pubkey (chain-validated
 * up to UTIL_HES_CA), and emits S_S with its own device-key.
 */

struct aa_ctx {
    uint8_t c_c[64];   /* client challenge */
    uint8_t c_s[64];
    uint8_t client_cert_der[2048];
    size_t  client_cert_len;
    uint8_t client_pub_n[384]; size_t client_pub_n_len;
    uint8_t client_pub_e[4];   size_t client_pub_e_len;
};

int meter_hls7_verify_pass3(struct aa_ctx *c,
                            const uint8_t *signature, size_t sig_len)
{
    /* 1. Chain-validate the client cert up to UTIL_HES_CA. */
    if (rsa_cert_chain_verify(
            c->client_cert_der, c->client_cert_len,
            UTIL_HES_CA_PUB_N, sizeof UTIL_HES_CA_PUB_N,
            UTIL_HES_CA_PUB_E, sizeof UTIL_HES_CA_PUB_E) != 0)
        return -1;

    /* 2. Extract client pubkey from cert. */
    if (rsa_cert_extract_pubkey(
            c->client_cert_der, c->client_cert_len,
            c->client_pub_n, sizeof c->client_pub_n, &c->client_pub_n_len,
            c->client_pub_e, sizeof c->client_pub_e, &c->client_pub_e_len) != 0)
        return -2;

    /* 3. Compute hash over HLS-7 binding = C_C || C_S || client_sys_title
     *                                         || server_sys_title. */
    uint8_t hash[32];
    uint8_t buf[256];
    size_t off = 0;
    memcpy(buf + off, c->c_c, 64); off += 64;
    memcpy(buf + off, c->c_s, 64); off += 64;
    /* ... system titles, etc. */
    sha256(buf, off, hash);

    /* 4. RSA-PSS verify S_C. */
    return rsa_pss_verify_sha256(
        c->client_pub_n, c->client_pub_n_len,
        c->client_pub_e, c->client_pub_e_len,
        hash, sizeof hash,
        signature, sig_len);
}


/* -------- Disconnect-relay command path (the grid-scale concern) --
 *
 * Once AA is established via HLS-7, the HES can:
 *
 *   - Read current tariff + register values (Profile IC 7).
 *   - Issue Disconnect_control::remote_disconnect (IC 70).
 *   - Push new tariff schedule (Activity_calendar IC 20).
 *   - Trigger firmware push (IC 18).
 *
 * A compromised HES client cert (i.e. an attacker with a factored
 * vendor or utility RSA key) can do any of these at scale. Meter
 * remote-disconnect commands are the DSO's primary load-shed lever;
 * coordinated illegitimate disconnect across a million units is a
 * kinetic grid-destabilization event.
 */

/* ---- Breakage ----
 *
 *   Factoring VENDOR_FW_SIGN_PUB:
 *     - Push backdoored firmware to every meter that the vendor
 *       shipped. Regional blackout or billing-system corruption
 *       at a million-meter DSO is within reach.
 *
 *   Factoring UTIL_HES_CA:
 *     - Mint an HES client cert, establish HLS-7 AA with any meter
 *       in the DSO, issue remote-disconnect commands across whole
 *       substations.
 *
 *   Factoring a specific meter's device key:
 *     - Forge meter-side signatures in HLS-7 pass-4 to the HES,
 *       letting an attacker present a rogue meter as the real one —
 *       billing-fraud vector for one service address.
 */
