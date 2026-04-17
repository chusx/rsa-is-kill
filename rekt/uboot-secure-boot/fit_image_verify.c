/*
 * fit_image_verify.c
 *
 * U-Boot FIT (Flattened Image Tree) signature verification.
 * U-Boot is the bootloader for ~90% of embedded Linux: NXP
 * i.MX, TI Sitara, Xilinx Zynq, Rockchip, Amlogic, NVIDIA
 * Jetson, Raspberry Pi Compute Module (CM4/CM5) — plus STB,
 * NAS, automotive IVI, industrial HMI, and telecom CPE.
 *
 * When CONFIG_FIT_SIGNATURE=y, U-Boot verifies RSA-2048/4096
 * signatures on the FIT image tree before booting the kernel +
 * DTB + initrd. The public key is compiled into U-Boot itself
 * (via its control DTB) at build time and is typically the OEM's
 * board-support-package signing key.
 */

#include <stdint.h>
#include <string.h>
#include "uboot.h"

/* The key node from U-Boot's control FDT:
 *   /signature/key-<keyname> {
 *     required = "image";
 *     algo = "sha256,rsa2048";
 *     rsa,num-bits = <2048>;
 *     rsa,modulus = <...>;        // RSA modulus
 *     rsa,exponent = <0x10001>;
 *     rsa,r-squared = <...>;      // Montgomery helper
 *     rsa,n0-inverse = <...>;     // Montgomery helper
 *   };
 */
struct uboot_rsa_key {
    uint32_t  num_bits;
    uint8_t   modulus[256];            /* n, big-endian          */
    uint8_t   exponent[4];            /* e, big-endian          */
    uint8_t   r_squared[256];
    uint32_t  n0_inverse;
};

/* FIT image structure (simplified from fdt):
 *   /images/kernel {
 *     data = <...>;
 *     hash { algo = "sha256"; value = <...>; };
 *   };
 *   /images/fdt {
 *     data = <...>;
 *     hash { algo = "sha256"; value = <...>; };
 *   };
 *   /configurations/conf-1 {
 *     kernel = "kernel";
 *     fdt = "fdt";
 *     signature {
 *       algo = "sha256,rsa2048";
 *       value = <256 bytes>;
 *       sign-images = "kernel","fdt";
 *     };
 *   };
 */
struct fit_config_sig {
    uint8_t   sig_value[256];          /* RSA-PKCS1v15-SHA256    */
    char      sign_images[4][16];
    uint8_t   n_images;
};

int fit_verify_configuration(const void *fit_fdt,
                              const struct uboot_rsa_key *key)
{
    /* (1) Hash each named image's data node. */
    uint8_t overall[32];
    sha256_init_ctx();
    for (int i = 0; i < fit_config_node_image_count(fit_fdt); ++i) {
        const void *data; size_t len;
        fit_get_image_data(fit_fdt, i, &data, &len);
        sha256_update(data, len);
    }
    sha256_final(overall);

    /* (2) RSA verify using compiled-in key. */
    struct fit_config_sig *s = fit_get_config_sig(fit_fdt);
    if (rsa_pkcs1v15_verify_sha256(
            key->modulus, key->num_bits / 8,
            key->exponent, 4,
            overall, 32,
            s->sig_value, key->num_bits / 8))
        return UBOOT_SIG_FAIL;

    /* (3) Rollback-index check if secure counter is provisioned. */
    uint32_t fit_idx = fit_get_rollback_index(fit_fdt);
    if (fit_idx < uboot_nvram_rollback())
        return UBOOT_ROLLBACK;

    return UBOOT_OK;
}

/* ---- Fleet-scale embedded device compromise ----------------
 *  OEM BSP signing key factored:
 *    - Forge a FIT image (kernel + DTB + initrd) for every
 *      board variant using that BSP key.
 *    - U-Boot verifies and boots the attacker kernel.
 *    - Persistence below the OS: attacker controls init, can
 *      hide from any userspace monitoring.
 *    - Targets: every NXP i.MX8-based industrial HMI, every
 *      Jetson-based AI-at-edge appliance, every Zynq-based
 *      5G small cell / RAN unit, every Amlogic STB at an ISP.
 *
 *  Recovery: OEM ships new U-Boot with new key -> requires
 *  reflashing the SPI/eMMC boot device, which on deployed
 *  hardware means truck-roll or (if OTA is available) an OTA
 *  that itself is authenticated by the broken key — bootstrap
 *  paradox. Some SoCs (i.MX HAB) fuse the hash of the RSA
 *  key into OTP, making recovery require silicon replacement.
 * --------------------------------------------------------- */
