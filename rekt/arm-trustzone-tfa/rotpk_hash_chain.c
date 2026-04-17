/*
 * rotpk_hash_chain.c
 *
 * ARM Trusted Firmware-A chain-of-trust walker. The BL1 ROM
 * holds SHA-256(ROTPK) in eFuse; each successive boot stage
 * (BL2 / BL31 / BL32 / BL33) is authenticated against a TBBR
 * content certificate signed by a key chained to ROTPK.
 *
 * This is the canonical TBBR-client.rst flow; the only novel
 * content here is the concrete struct layout and the order
 * in which BL1 validates things — because an attacker with
 * a factored ROTPK forges the entire chain.
 *
 * TBBR = Trusted Board Boot Requirements (ARM DEN0006D-C).
 * cot_def.c in upstream TF-A generates the cert graph.
 */

#include <stdint.h>
#include <string.h>
#include "tbbr.h"

/* eFuse layout (ARMv8-A reference SoC):
 *  0x000-0x01F : ROTPK_HASH (32 B, SHA-256(DER(SPKI)))
 *  0x020-0x02F : TRUSTED_BOOT_ENABLE flags
 *  0x030-0x04F : HUK (hardware unique key, sealed)
 *  0x050-0x053 : ROLLBACK counter (32 bits)
 *  0x054-0x073 : FIP_DEV_UUID
 */

#define EFUSE_ROTPK_OFF      0x000
#define EFUSE_ROLLBACK_OFF   0x050
#define EFUSE_BOOT_FLAGS_OFF 0x020

#define TBBR_BL2_CERT_ID       0x01
#define TBBR_TRUSTED_KEY_CERT  0x02
#define TBBR_BL31_KEY_CERT     0x03
#define TBBR_BL31_CONTENT_CERT 0x04
#define TBBR_BL32_KEY_CERT     0x05
#define TBBR_BL32_CONTENT_CERT 0x06
#define TBBR_BL33_KEY_CERT     0x07
#define TBBR_BL33_CONTENT_CERT 0x08

struct content_cert {
    uint8_t  cert_type;
    uint32_t nv_ctr;                   /* anti-rollback counter  */
    uint8_t  hash_image[32];           /* SHA-256 of BLx image   */
    uint8_t  subject_pk[294];          /* DER SPKI, RSA-2048     */
    uint8_t  sig_alg_oid[16];          /* 1.2.840.113549.1.1.11  */
    uint8_t  sig[256];                 /* RSA-PKCS#1 v1.5 SHA-256*/
};

/* Walk the TBBR cert graph from BL1. Every link is RSA. */
int tbbr_authenticate_chain(const struct fip_toc *toc)
{
    uint8_t rotpk_hash[32];
    if (efuse_read(EFUSE_ROTPK_OFF, rotpk_hash, 32)) return -1;

    /* Level 1: Trusted Key certificate (root). Its subject_pk
     * hash must equal rotpk_hash from eFuse. */
    const struct content_cert *tkc = fip_find(toc, TBBR_TRUSTED_KEY_CERT);
    uint8_t spki_hash[32];
    sha256(tkc->subject_pk, sizeof tkc->subject_pk, spki_hash);
    if (memcmp(spki_hash, rotpk_hash, 32)) return -2;
    if (tkc->nv_ctr < read_nv_counter()) return -3;

    /* tkc is self-signed against ROTPK. Verify. */
    if (rsa_pkcs1v15_verify_sha256(
            tkc->subject_pk, sizeof tkc->subject_pk,
            tkc, offsetof(struct content_cert, sig),
            tkc->sig, sizeof tkc->sig))
        return -4;

    /* Level 2: BL31 content cert signed by Trusted World Key. */
    const struct content_cert *bl31 = fip_find(toc, TBBR_BL31_CONTENT_CERT);
    if (rsa_pkcs1v15_verify_sha256(
            tkc->subject_pk, sizeof tkc->subject_pk,
            bl31, offsetof(struct content_cert, sig),
            bl31->sig, sizeof bl31->sig))
        return -5;

    /* Now authenticate the actual BL31 image payload against
     * bl31->hash_image. Same pattern repeats for BL32 (OP-TEE)
     * and BL33 (U-Boot/UEFI). */
    uint8_t img_hash[32];
    sha256(fip_image_ptr(toc, "bl31.bin"),
           fip_image_len(toc, "bl31.bin"), img_hash);
    if (memcmp(img_hash, bl31->hash_image, 32)) return -6;

    update_nv_counter(bl31->nv_ctr);   /* monotonic fuse burn */
    return 0;
}

/* ---------------------------------------------------------
 *  Attack once ROTPK is recovered by factoring its RSA key:
 *
 *  1. Construct a fresh Trusted Key cert with attacker's
 *     subject_pk whose SHA-256 equals the eFused rotpk_hash
 *     — trivially satisfied because the attacker possesses
 *     the genuine private key corresponding to rotpk_hash.
 *  2. Sign BL31 / BL32 / BL33 content certs under that key.
 *  3. Ship as FIP; every SoC booting this silicon family
 *     executes the attacker's EL3 monitor and secure world
 *     with no runtime indicator of compromise.
 *
 *  Because ROTPK_HASH is eFused, recovery requires silicon
 *  revision. Mass AWS Graviton, Pixel, Samsung Exynos, and
 *  Ampere Altra fleets fall into this class.
 * --------------------------------------------------------- */
