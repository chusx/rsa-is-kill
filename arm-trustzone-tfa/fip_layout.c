/*
 * fip_layout.c
 *
 * Arm Trusted Firmware-A (TF-A) FIP (Firmware Image Package) layout and
 * boot-time verification sequence invoked by every SoC that uses TF-A
 * as its BL1/BL2/BL31 (Qualcomm Snapdragon, MediaTek Dimensity, NXP
 * i.MX, Rockchip, Xilinx Zynq/Versal, Marvell OCTEON, Nvidia Tegra,
 * Ampere Altra, AWS Graviton, Apple tvOS bootchain on Arm server).
 *
 * The RSA verification primitives live in `tbbr_verify.c`; this file
 * shows where each RSA check fires inside the boot sequence so the
 * blast radius of an RSA break is obvious.
 */

#include <stdint.h>
#include <string.h>

#define FIP_TOC_MAGIC           0xAA640001

/*
 * FIP layout — emitted by fiptool at build time:
 *
 *   [ ToC Header ][ ToC Entry 0 ][ ToC Entry 1 ] ... [ ToC Entry N ]
 *   [ Image 0 ][ Image 1 ] ... [ Image N ]
 *
 * Each ToC Entry carries a UUID identifying the image type:
 *   UUID_TRUSTED_BOOT_FW_CERT     — signed by ROTPK (fused)
 *   UUID_TRUSTED_KEY_CERT         — signed by ROTPK, authorizes BL31/BL32 keys
 *   UUID_SOC_FW_KEY_CERT          — signed by Trusted Key
 *   UUID_SOC_FW_CONTENT_CERT      — signed by SoC FW Key
 *   UUID_EL3_RUNTIME_FIRMWARE_BL31
 *   UUID_SECURE_RT_EL1_FIRMWARE_BL32   (OP-TEE, Trusty, or SPM)
 *   UUID_NON_TRUSTED_FIRMWARE_BL33     (U-Boot, UEFI)
 *
 * Every _CERT entry is an X.509 (RFC 5280) cert with RSA-2048 or
 * RSA-4096 signatures per TBBR-CLIENT. Every _FIRMWARE entry is hash-
 * referenced from a content cert. Break RSA → forge the full chain
 * → replace BL31/BL32/BL33 with attacker images → pwn EL3 forever.
 */

struct fip_toc_header {
    uint32_t name;          /* 'T','O','C',' ' */
    uint32_t serial_number;
    uint64_t flags;
};

struct fip_toc_entry {
    uint8_t  uuid[16];
    uint64_t offset_address;
    uint64_t size;
    uint64_t flags;
};

/* TF-A boot-time auth sequence invoked from bl2_main() → auth_mod_verify_img().
 * Each step is an RSA verification against TBBR-CLIENT chain rooted at the
 * SoC's fused ROTPK hash. */
enum tbbr_auth_steps {
    TBBR_STEP_VERIFY_TRUSTED_BOOT_FW_CERT      = 1,  /* RSA: ROTPK -> Trusted Boot Cert */
    TBBR_STEP_VERIFY_TRUSTED_KEY_CERT          = 2,  /* RSA: ROTPK -> Trusted Key Cert */
    TBBR_STEP_VERIFY_SOC_FW_KEY_CERT           = 3,  /* RSA: Trusted Key -> SoC FW Key Cert */
    TBBR_STEP_VERIFY_SOC_FW_CONTENT_CERT       = 4,  /* RSA: SoC FW Key -> Content Cert */
    TBBR_STEP_HASH_BL31                        = 5,  /* SHA-256, compared to content cert */
    TBBR_STEP_VERIFY_TRUSTED_OS_FW_KEY_CERT    = 6,  /* RSA for OP-TEE/Trusty image */
    TBBR_STEP_VERIFY_TRUSTED_OS_FW_CONTENT     = 7,  /* RSA for OP-TEE/Trusty image */
    TBBR_STEP_HASH_BL32                        = 8,  /* SHA-256 */
    TBBR_STEP_VERIFY_NT_FW_CONTENT_CERT        = 9,  /* RSA for BL33 */
    TBBR_STEP_HASH_BL33                        = 10, /* SHA-256 */
};

/*
 * Fused ROTPK (Root Of Trust Public Key) hash — stored in SoC OTP.
 * Typical hardware: 32 bytes SHA-256 of the DER-encoded RSA-4096
 * modulus + exponent. Cannot be reprogrammed post-production.
 *
 * If the RSA algorithm behind ROTPK is broken, the fused hash is
 * still "valid" — the attacker simply computes a different RSA key
 * whose public modulus hashes to the same value (impossible with a
 * second-preimage-resistant hash), or more realistically factors the
 * legitimate modulus and signs arbitrary certs under it. Either way,
 * EL3 falls.
 */

/*
 * Downstream trust-domain consumers that inherit this chain:
 *   - Android Trusty / Qualcomm QSEE / Samsung TEEGRIS (see autosar-ecu-hsm/)
 *   - Google Titan-M / Pixel bootchain (Tensor G-series SoC)
 *   - iOS boot ROM + iBoot (closely related, mostly RSA-2048 / 4096)
 *   - AWS Nitro / Graviton boot on Arm (BL1 signed under AWS Root)
 *   - Ampere Altra + Oracle OCI A1 Ampere nodes
 *   - Nvidia Jetson AGX Orin (automotive/robotics AI — see ros2-sros2-dds/)
 */
