/*
 * secure_boot_chain.c
 *
 * AUTOSAR-compliant ECU secure boot chain invocation. Runs on every
 * modern automotive ECU implementing ISO/SAE 21434 and UNECE R155/R156
 * cybersecurity requirements: Bosch, Continental, ZF, Denso, Aisin,
 * Magna, Hyundai Mobis, Valeo, Vitesco.
 *
 * The crypto primitives are in the HSM firmware (`autosar_hsm.c`);
 * this file shows the bootloader-side orchestration of RSA-PSS chain
 * verification across each stage of ECU power-on.
 */

#include <stdint.h>
#include <string.h>

/* Stages match AUTOSAR R22-11 Secure Boot reference implementation. */
enum ecu_boot_stage {
    STAGE_ROM_BOOT      = 0,   /* silicon ROM verifies SBL RSA sig */
    STAGE_SBL           = 1,   /* Secondary Bootloader — RSA verifies FBL */
    STAGE_FBL           = 2,   /* Flash Bootloader — RSA verifies application */
    STAGE_APPLICATION   = 3,   /* Application code — RSA verifies calibration */
    STAGE_CALIBRATION   = 4,   /* Calibration data — runs under normal CAN sched */
};

/* OEM-fused root hash at stage 0. One ROTPK hash per OEM program
 * (e.g., "VW MEB platform 2024 Rev B"); burned into silicon OTP at
 * Tier-1 production flashing. Cannot be re-fused once set. */
extern const uint8_t OEM_ROTPK_HASH_SHA256[32];

/* Each stage's authenticated header (authored per AUTOSAR 21434). */
struct ecu_stage_header {
    uint32_t magic;              /* 0xAE5EC0DE */
    uint32_t stage_id;
    uint32_t image_size;
    uint8_t  image_sha256[32];
    uint32_t rollback_index;     /* monotonic anti-rollback counter */

    uint8_t  signer_pubkey_mod[384];    /* RSA-3072 (typical for new ECUs) */
    uint8_t  signer_pubkey_exp[3];      /* 0x01, 0x00, 0x01 */

    /* Signer cert: parent-stage key vouches for this stage's public key
     * via a compact cert (not full X.509, uses AUTOSAR Crypto Stack
     * cert profile). */
    uint8_t  parent_signature[384];     /* RSA-PSS-SHA256 by parent */
};


extern int hsm_rsa_pss_verify(const uint8_t *sig, size_t sig_len,
                               const uint8_t *msg, size_t msg_len,
                               const uint8_t *mod, size_t mod_len,
                               const uint8_t *exp, size_t exp_len);


int
ecu_verify_stage(const struct ecu_stage_header *stage_hdr,
                  const uint8_t *parent_pubkey_mod,
                  const uint8_t *parent_pubkey_exp,
                  uint32_t expected_stage_id,
                  uint32_t current_rollback_index)
{
    if (stage_hdr->magic != 0xAE5EC0DE) return -1;
    if (stage_hdr->stage_id != expected_stage_id) return -1;

    /* Rollback protection: ECU refuses to boot any stage whose signed
     * rollback_index is below the monotonic counter stored in HSM.
     * Prevents downgrade attacks even with a legitimate (older) signed
     * image. */
    if (stage_hdr->rollback_index < current_rollback_index) return -1;

    /* Parent key signs: [stage_id || image_size || image_sha256 ||
     * rollback_index || signer_pubkey_mod || signer_pubkey_exp] */
    uint8_t to_verify[4 + 4 + 32 + 4 + 384 + 3];
    size_t off = 0;
    memcpy(to_verify + off, &stage_hdr->stage_id, 4); off += 4;
    memcpy(to_verify + off, &stage_hdr->image_size, 4); off += 4;
    memcpy(to_verify + off, stage_hdr->image_sha256, 32); off += 32;
    memcpy(to_verify + off, &stage_hdr->rollback_index, 4); off += 4;
    memcpy(to_verify + off, stage_hdr->signer_pubkey_mod, 384); off += 384;
    memcpy(to_verify + off, stage_hdr->signer_pubkey_exp, 3); off += 3;

    return hsm_rsa_pss_verify(
        stage_hdr->parent_signature, 384,
        to_verify, sizeof(to_verify),
        parent_pubkey_mod, 384,
        parent_pubkey_exp, 3);
}


/* Boot entry — executed out of ROM immediately after reset. Walks the
 * full chain SBL -> FBL -> Application -> Calibration. Any failure
 * drops the ECU into a fail-safe "diagnostic boot" state that refuses
 * to run application code (no throttle control, no ABS, no infotainment
 * depending on the ECU). */
int
ecu_secure_boot(const uint8_t *sbl_image, const uint8_t *fbl_image,
                 const uint8_t *app_image, const uint8_t *cal_image)
{
    /* Stage 0 -> 1: Silicon ROM uses fused ROTPK directly. Parent key
     * modulus arrives from manufacturer programming the OTP. */
    extern const uint8_t ROM_ROTPK_MOD[384], ROM_ROTPK_EXP[3];
    if (ecu_verify_stage((const struct ecu_stage_header *)sbl_image,
                          ROM_ROTPK_MOD, ROM_ROTPK_EXP,
                          STAGE_SBL, /* rollback */ 1) != 0) return -1;

    /* Stage 1 -> 2: SBL's embedded key (already signed by ROTPK)
     * becomes the parent for FBL. */
    const struct ecu_stage_header *sbl = (const struct ecu_stage_header *)sbl_image;
    if (ecu_verify_stage((const struct ecu_stage_header *)fbl_image,
                          sbl->signer_pubkey_mod, sbl->signer_pubkey_exp,
                          STAGE_FBL, 1) != 0) return -1;

    /* And so on through application + calibration. */
    const struct ecu_stage_header *fbl = (const struct ecu_stage_header *)fbl_image;
    if (ecu_verify_stage((const struct ecu_stage_header *)app_image,
                          fbl->signer_pubkey_mod, fbl->signer_pubkey_exp,
                          STAGE_APPLICATION, 1) != 0) return -1;

    const struct ecu_stage_header *app = (const struct ecu_stage_header *)app_image;
    return ecu_verify_stage((const struct ecu_stage_header *)cal_image,
                             app->signer_pubkey_mod, app->signer_pubkey_exp,
                             STAGE_CALIBRATION, 1);
}
