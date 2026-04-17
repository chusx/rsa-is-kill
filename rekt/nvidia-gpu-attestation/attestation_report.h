/*
 * attestation_report.h
 *
 * Layout of the NVIDIA GPU Attestation Report as produced by the
 * Hopper/Blackwell on-die Remote Attestation Engine (RAE).
 *
 * Sources:
 *   - NVIDIA Confidential Compute Deployment Guide (H100/H200/B100/B200)
 *   - NVIDIA Verifier Library (nvtrust) public headers
 *   - NVIDIA Attestation Service (NRAS) API contract
 *
 * A report has three concatenated sections:
 *
 *   [ RIM ID + measurements ]  (who am I, firmware hashes, mode flags)
 *   [ Nonce + timestamp     ]  (freshness)
 *   [ RSA-3072 signature    ]  (over SHA-384 of preceding fields,
 *                               by device-unique attestation key)
 *
 * The accompanying cert chain:
 *
 *   GPU Attestation Leaf  (RSA-3072, device-unique, per-GPU fused key)
 *          |
 *   NVIDIA Attestation Intermediate CA  (RSA-3072)
 *          |
 *   NVIDIA Attestation Root CA          (RSA-4096, offline in NVIDIA HSM)
 *
 * The Root CA public key modulus is embedded in:
 *   - Every shipped H100/H200/B100/B200 GPU (fuse-burned, read-only)
 *   - The nvtrust Python SDK distributed under NVIDIA developer login
 *   - Azure / GCP / OCI confidential-GPU verifier policies
 *   - On-prem Verifier appliances from Fortanix, HashiCorp Vault, Thales
 */

#ifndef NVIDIA_ATTESTATION_REPORT_H
#define NVIDIA_ATTESTATION_REPORT_H

#include <stdint.h>

#define NV_ATTEST_NONCE_BYTES       32
#define NV_ATTEST_SIG_BYTES         384    /* RSA-3072 signature */
#define NV_ATTEST_MAX_PCR_COUNT     24
#define NV_ATTEST_PCR_BYTES         48     /* SHA-384 */
#define NV_ATTEST_RIM_ID_BYTES      32

#define NV_CC_MODE_OFF              0
#define NV_CC_MODE_ON               1
#define NV_CC_MODE_DEVTOOLS         2      /* allows debug; rejected in prod */

/* Reference Integrity Manifest (RIM) identifier — hash of
 * "vendor|product|firmware_version" signed by NVIDIA; the verifier looks
 * up policy entries by this ID. */
struct nv_rim_id {
    uint8_t bytes[NV_ATTEST_RIM_ID_BYTES];
};

/* Measurements — like TPM PCR banks, but signed by the GPU's own RAE. */
struct nv_measurement {
    uint32_t index;
    uint8_t  algorithm;        /* 12 = SHA-384 */
    uint8_t  value[NV_ATTEST_PCR_BYTES];
};

struct nv_attest_report_body {
    uint8_t  version;                  /* 1 for H100-era, 2 for Blackwell */
    uint8_t  gpu_arch;                 /* 9 = Hopper, 10 = Blackwell */
    uint8_t  cc_mode;                  /* NV_CC_MODE_* */
    uint8_t  reserved0;

    uint8_t  gpu_uuid[16];             /* device-unique */
    uint8_t  board_serial[16];
    uint32_t vbios_version;
    uint32_t gsp_firmware_version;     /* Hopper GSP firmware */
    uint32_t hwprotection_firmware;    /* runtime enforcement FW */

    struct nv_rim_id rim;

    uint32_t measurement_count;
    struct nv_measurement measurements[NV_ATTEST_MAX_PCR_COUNT];

    uint8_t  nonce[NV_ATTEST_NONCE_BYTES];  /* supplied by verifier */
    uint64_t timestamp_ms;                  /* GPU's secure time */

    uint32_t flags;   /* bit 0: NVLink topology locked
                       * bit 1: spdm session bound
                       * bit 2: debug fuses blown
                       * bit 3: ppcie protected range active */
};

struct nv_attest_report {
    struct nv_attest_report_body body;

    /* RSA-3072 signature over SHA-384(body), PKCS#1 v1.5.
     * Verifier walks device_cert -> intermediate -> NV Attestation Root. */
    uint8_t signature[NV_ATTEST_SIG_BYTES];

    /* DER-encoded X.509 cert chain appended (variable length):
     *   [leaf device cert][intermediate][root is pre-trusted] */
    uint32_t cert_chain_len;
    uint8_t  cert_chain_der[0];   /* flexible array */
};

/* NVIDIA Attestation Root public key (RSA-4096) modulus — embedded in
 * every Hopper/Blackwell GPU and in the nvtrust verifier. */
extern const uint8_t NVIDIA_ATTEST_ROOT_MODULUS[512];
extern const uint8_t NVIDIA_ATTEST_ROOT_EXPONENT[3];   /* 0x01 0x00 0x01 */

/* Verifier API — implemented in `nvml_attestation.c`.
 * Returns 0 on success (report genuine, GPU in CC mode, measurements
 * match expected RIM policy), negative on failure. */
int nv_verify_attestation_report(const struct nv_attest_report *report,
                                  const uint8_t expected_nonce[NV_ATTEST_NONCE_BYTES],
                                  const struct nv_rim_id *expected_rim);

#endif /* NVIDIA_ATTESTATION_REPORT_H */
