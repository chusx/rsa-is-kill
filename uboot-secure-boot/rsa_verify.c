/* Source: u-boot/u-boot lib/rsa/rsa-verify.c + lib/rsa/rsa-sign.c
 *
 * U-Boot is the bootloader for virtually every embedded Linux board:
 * Raspberry Pi, BeagleBone, i.MX (NXP), AM335x (TI), Rockchip RK3*, Allwinner,
 * Nvidia Tegra, and hundreds of others. It runs before the OS kernel.
 *
 * U-Boot Verified Boot uses RSA-2048 (or RSA-4096) to authenticate the
 * Flattened Image Tree (FIT) before booting the kernel. The RSA public key
 * is baked into the bootloader binary itself (in the device tree blob).
 *
 * This is the lowest level of the boot trust chain. If RSA is broken,
 * the entire secure boot chain collapses — even before the OS loads.
 * There is no PQC algorithm support in U-Boot Verified Boot.
 */

/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2013, Google Inc. */

#include <u-boot/rsa.h>
#include <u-boot/rsa-mod-exp.h>

#define RSA_DEFAULT_PUBEXP  65537

/* struct rsa_public_key — embedded in the U-Boot FDT at build time.
 * The modulus[] and rr[] arrays are the RSA-2048 (or RSA-4096) key material.
 * There is no mechanism to update this key after the bootloader is flashed. */
struct rsa_public_key {
    uint     len;        /* len of modulus[] in number of uint32_t */
    uint32_t n0inv;      /* -1 / modulus[0] mod 2^32 */
    uint32_t *modulus;   /* modulus as little endian array */
    uint32_t *rr;        /* R^2 as little endian array */
    uint64_t exponent;   /* public exponent (typically 65537) */
};

/* rsa_verify_key() — verify FIT image signature at boot time.
 * Called by fit_image_verify_required_sigs() for every boot.
 * @prop:    RSA public key embedded in U-Boot's own FDT
 * @sig:     Signature from FIT image header
 * @sig_len: Expected = prop->num_bits / 8 (256 for RSA-2048)
 * @hash:    SHA-256 hash of the image data
 * @padding: PKCS1.5 or PSS padding verifier (no PQC verifier exists)
 */
static int rsa_verify_key(struct image_sign_info *info,
                          const struct rsa_public_key *prop,
                          const uint8_t *sig, uint32_t sig_len,
                          const uint8_t *hash, struct checksum_algo *algo,
                          const struct padding_algo *padding,
                          uint32_t key_len)
{
    uint8_t buf[RSA_MAX_SIG_BITS / 8];
    int ret;

    if (sig_len != (prop->num_bits / 8)) {
        debug("Signature is wrong length: %d vs %d\n", sig_len, prop->num_bits / 8);
        return -EINVAL;
    }

    if (sig_len > RSA_MAX_SIG_BITS / 8) {
        debug("Signature length %u exceeds maximum %d\n", sig_len, RSA_MAX_SIG_BITS / 8);
        return -EINVAL;
    }

    /* Modular exponentiation: buf = sig^e mod n (RSA public key operation)
     * Implemented in hardware on some SoCs via drivers/crypto/rsa_mod_exp/
     * No PQC equivalent exists; ML-DSA verification is a completely different operation */
    ret = info->crypto->rsa_mod_exp(info, sig, sig_len, prop, buf);
    if (ret) {
        debug("rsa_mod_exp() failed: %d\n", ret);
        return ret;
    }

    /* Verify PKCS#1 v1.5 or PSS padding + hash */
    ret = padding->verify(info, buf, key_len, hash, algo->checksum_len);
    if (ret) {
        debug("In RSAVerify(): Padding check failed!\n");
        return ret;
    }

    return 0;
}

/* rsa_sign() — used by mkimage (host tool) to sign FIT images during build.
 * The RSA private key is held by the build system / release engineering HSM.
 * The corresponding public key is embedded into U-Boot at build time. */
int rsa_sign(struct image_sign_info *info,
             const struct image_region region[],
             int region_count, uint8_t **sigp, uint *sig_len)
{
    EVP_PKEY *key = NULL;
    RSA *rsa;
    int ret;

    ret = rsa_get_priv_key(info->keydir, info->keyname, info->engine, &key);
    if (ret)
        goto err_priv;

    rsa = EVP_PKEY_get1_RSA(key);   /* RSA private key for PKCS#1 v1.5 signing */
    if (!rsa) {
        ret = rsa_err("Couldn't get RSA key");
        goto err_rsa;
    }

    ret = rsa_sign_with_key(rsa, info->padding, info->checksum,
                            region, region_count, sigp, sig_len);
    /* *sig_len = RSA_size(rsa); — 256 bytes for RSA-2048, 512 for RSA-4096 */

err_rsa:
    EVP_PKEY_free(key);
err_priv:
    return ret;
}

/*
 * Affected boards (representative sample):
 *   - Raspberry Pi (CM4, Pi 5) — Broadcom BCM2712
 *   - BeagleBone Black — TI AM335x
 *   - NXP i.MX 8M, i.MX 6 — automotive, industrial
 *   - Rockchip RK3588 — embedded AI/SBC boards
 *   - Allwinner H616 — Android TV boxes, industrial displays
 *   - TI AM62x — industrial IoT gateways
 *
 * The bootloader RSA key is burned into boot media (eMMC, SD card) as part
 * of the board bringup. Replacing the key requires reflashing U-Boot with
 * a new key embedded in the FDT. On locked/eFUSE devices, the key cannot
 * be changed after provisioning.
 */
