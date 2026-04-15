/*
 * fit_image_boot_flow.c
 *
 * How `rsa_verify.c` is actually driven across U-Boot's FIT-image
 * signed-boot chain. U-Boot is the dominant bootloader on:
 *
 *   - Nearly every ARM SoC-based embedded Linux product: home routers
 *     (ASUS, TP-Link, Netgear, Ubiquiti), set-top boxes (Roku, Amazon
 *     Fire TV, Android TV OEM devices), network switches (Cumulus,
 *     Cisco Nexus CBS, Juniper QFX 5000-series), industrial
 *     gateways (Siemens IoT2050, Moxa, Advantech)
 *   - Every NVIDIA Jetson (Orin NX / Nano / AGX): U-Boot sits between
 *     cboot and Linux
 *   - Every Raspberry Pi Compute Module deployed in production
 *   - In-vehicle Linux units from Tesla, Rivian, Stellantis, Ford
 *     SYNC 4 (post-2020)
 *   - Most OpenWrt-based gear, regardless of vendor.
 *
 * Chain: SoC ROM → SPL (pre-boot) → U-Boot proper → FIT image
 * (kernel + devicetree + initramfs) → kernel. RSA-2048 or RSA-4096
 * signatures gate every transition after the SPL.
 */

#include <common.h>
#include <image.h>
#include <u-boot/rsa.h>
#include <u-boot/rsa-checksum.h>

/* SoC ROM verifies SPL under a fused OTP hash of the ROTPK (Root-Of-
 * Trust Public Key). SPL then relocates and verifies U-Boot proper
 * using the same primitive — the RSA public modulus is either (a)
 * embedded in SPL's dtb / "control FDT", or (b) read from a fused
 * OTP slot that SPL consults over the SoC-specific trust-provisioning
 * interface. */

int spl_load_and_verify_uboot(struct spl_image_info *spl_image,
                              struct spl_boot_device *bootdev)
{
    void *uboot_fit = load_image_from_mmc(bootdev);
    if (!uboot_fit) return -EIO;

    /* fit_image_verify_required_sigs() walks /configurations/*/signature*
     * nodes, each of which references a key node under /signature/key-*
     * in the *control* FDT baked into SPL. Each signature is an
     * RSA-2048 or RSA-4096 PKCS#1 v1.5 SHA-256 sig over the image
     * configuration's hashed sub-images. */
    int verify_rc = fit_image_verify_required_sigs(uboot_fit, 0,
                                                   gd_fdt_blob(),
                                                   NULL);
    if (verify_rc < 0) {
        printf("SPL: U-Boot FIT signature verify FAILED (%d)\n",
               verify_rc);
        hang();   /* pull reset, do not boot */
    }

    /* Measured boot extension into TPM2 PCR[0] */
    tpm2_extend_pcr(0, sha256(uboot_fit, fit_size(uboot_fit)));

    return spl_parse_image_header(spl_image, uboot_fit);
}

/* Once U-Boot runs, `bootm` / `boot_fit_config` validates the kernel
 * FIT under a *second* key hierarchy rolled into U-Boot's own dtb.
 * On most production devices this is the OEM-held signing key (a.k.a.
 * "software publisher" key), distinct from the SoC ROTPK.
 */

int do_bootm_fit(cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[])
{
    unsigned long addr = simple_strtoul(argv[1], NULL, 16);
    const void *fit = (void *)addr;

    /* 1. Pick named config (per board, per A/B slot). */
    int cfg_noffset = fit_conf_get_node(fit, "conf-1");

    /* 2. fit_config_verify_required_sigs() loops each required
     *    signature node and calls into rsa_verify() in
     *    `rsa_verify.c`. */
    if (fit_config_verify_required_sigs(fit, cfg_noffset,
                                         gd_fdt_blob()) < 0) {
        printf("FIT: kernel config sig FAILED — refusing boot\n");
        return CMD_RET_FAILURE;
    }

    /* 3. Each sub-image (kernel, fdt, ramdisk) also has hash nodes
     *    verified against the config's signed hash-list. */
    const void *kernel; size_t klen;
    if (fit_image_load(fit, IH_TYPE_KERNEL, &kernel, &klen) < 0)
        return CMD_RET_FAILURE;

    tpm2_extend_pcr(8, sha256(kernel, klen));

    /* 4. Jump to kernel. Kernel module signing (CONFIG_MODULE_SIG=y)
     *    takes over from here; see shim-uefi/ for the module-sig
     *    primitive. */
    boot_jump_linux(&images, 0);
    return CMD_RET_SUCCESS;
}

/* Boot-chain rollback protection via fused OTP monotonic counter.
 * U-Boot refuses any FIT whose `rollback-index` is below the one
 * fused into the SoC, preventing attackers from downgrading to a
 * prior signed-but-vulnerable image. The counter is authenticated
 * by being inside the signed FIT config node. */

/* ---- A/B slot decision + boot_count integration ----------------
 *
 *   slot = current_slot();
 *   if (spl_load_and_verify_uboot(&spl_image, slot_dev(slot)) < 0) {
 *       mark_slot_bad(slot);
 *       slot = other_slot(slot);
 *       spl_load_and_verify_uboot(&spl_image, slot_dev(slot));
 *   }
 */


/* ---- Breakage -------------------------------------------------
 *
 * Factoring attack consequences per trust-anchor:
 *
 *   - **SoC ROTPK** (OEM master key fused in every unit of a given
 *     product line): attacker signs a malicious SPL that the SoC ROM
 *     accepts. Permanent bootkit on every unit ever manufactured;
 *     no firmware update, no field-service operation short of chip
 *     replacement recovers. Product-line-wide.
 *
 *   - **OEM software-publisher key** (the one inside U-Boot's
 *     control dtb): attacker signs a kernel+dtb+initramfs that
 *     U-Boot proper accepts. Same blast radius but one level
 *     shallower — recoverable by re-flashing a new SPL + U-Boot
 *     over a secure production-line port that many products don't
 *     expose post-manufacture.
 *
 *   - **A/B slot-specific key** (rare but exists for staged roll-
 *     outs): attacker poisons one slot; good-slot boots remain
 *     safe until A/B decision promotes the poisoned image.
 *
 * Every IoT fleet running U-Boot FIT-signed boot (billions of
 * devices in aggregate) is a post-quantum-transition concern
 * because hardware ROTPKs are not upgradable.
 */
