/* Source: ARM-software/arm-trusted-firmware
 *   drivers/auth/mbedtls/mbedtls_crypto.c
 *   drivers/nxp/crypto/caam/src/auth/rsa.c
 *
 * ARM Trusted Firmware-A (TF-A) is the reference secure world firmware for
 * ARMv8-A processors. It implements the Trusted Board Boot (TBB) chain:
 *   BL1 (ROM) → BL2 → BL31 (EL3 runtime) → BL32 (OP-TEE) → BL33 (U-Boot/UEFI)
 *
 * Every firmware image in the chain is authenticated by a ROTPK
 * (Root-Of-Trust Public Key) — typically RSA-2048 or ECDSA-P256 — before
 * being allowed to execute. The ROTPK hash is burned into OTP fuses at
 * manufacturing and cannot be changed.
 *
 * Affected SoCs (TF-A is used on):
 *   - Raspberry Pi 4/5 (BCM2711/BCM2712) — VideoCore bootrom uses TF-A concepts
 *   - NXP i.MX 8M, i.MX 93, LS1046A, LX2160A (data center, automotive)
 *   - Rockchip RK3568/RK3588 — industrial AI edge boxes
 *   - Marvell OCTEON TX2 — data center SmartNICs
 *   - MediaTek Dimensity (mobile SoCs)
 *   - STM32MP1 — industrial microprocessors
 *
 * No PQC algorithm is supported by TF-A. The TBBR (Trusted Board Boot
 * Requirements) specification (ARM DEN0006) does not define PQC ROTPK formats.
 */

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2025, ARM Limited and Contributors. All rights reserved. */

#include <mbedtls/pk.h>
#include <mbedtls/x509.h>
#include <mbedtls/asn1.h>
#include <mbedtls/md.h>
#include <drivers/auth/crypto_mod.h>

/*
 * verify_signature() — authenticate a firmware image.
 * Called by auth_mod_verify_img() for every BL image in the boot chain.
 *
 * @data_ptr, data_len: firmware image payload
 * @sig_ptr, sig_len:   RSA or ECDSA signature from the FIP (Firmware Image Package)
 * @pk_ptr, pk_len:     DER-encoded SubjectPublicKeyInfo (ROTPK or intermediate key)
 *
 * The pk_alg is parsed from the certificate's AlgorithmIdentifier.
 * For the vast majority of production deployments: pk_alg = MBEDTLS_PK_RSA.
 */
static int verify_signature(void *data_ptr, unsigned int data_len,
                             void *sig_ptr,  unsigned int sig_len,
                             void *sig_alg,  unsigned int sig_alg_len,
                             void *pk_ptr,   unsigned int pk_len)
{
    mbedtls_asn1_buf sig_oid, sig_params, signature;
    mbedtls_md_type_t  md_alg;
    mbedtls_pk_type_t  pk_alg;     /* MBEDTLS_PK_RSA or MBEDTLS_PK_ECDSA */
    mbedtls_pk_context pk = {0};
    void *sig_opts = NULL;
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    unsigned char *p, *end;
    int rc;

    /* Parse AlgorithmIdentifier (e.g., sha256WithRSAEncryption OID) */
    p = (unsigned char *)sig_alg;
    end = p + sig_alg_len;
    rc = mbedtls_asn1_get_alg(&p, end, &sig_oid, &sig_params);
    if (rc != 0) return CRYPTO_ERR_SIGNATURE;

    rc = mbedtls_x509_get_sig_alg(&sig_oid, &sig_params, &md_alg, &pk_alg, &sig_opts);
    if (rc != 0) return CRYPTO_ERR_SIGNATURE;

    /* Parse SubjectPublicKeyInfo — RSA-2048 or ECDSA-P256/P384 */
    mbedtls_pk_init(&pk);
    p = (unsigned char *)pk_ptr;
    end = p + pk_len;
    rc = mbedtls_pk_parse_subpubkey(&p, end, &pk);
    if (rc != 0) { rc = CRYPTO_ERR_SIGNATURE; goto end2; }

    /* Parse DER signature bitstring */
    p = (unsigned char *)sig_ptr;
    end = p + sig_len;
    signature.tag = *p;
    rc = mbedtls_asn1_get_bitstring_null(&p, end, &signature.len);
    if (rc != 0 || (size_t)(end - p) != signature.len) {
        rc = CRYPTO_ERR_SIGNATURE; goto end1;
    }
    signature.p = p;

    /* Hash the firmware payload */
    rc = mbedtls_md(mbedtls_md_info_from_type(md_alg),
                    (unsigned char *)data_ptr, data_len, hash);
    if (rc != 0) { rc = CRYPTO_ERR_SIGNATURE; goto end1; }

    /* Verify: RSA PKCS#1 v1.5 or PSS (pk_alg == MBEDTLS_PK_RSA)
     *         ECDSA P-256 / P-384 (pk_alg == MBEDTLS_PK_ECDSA)
     * Both are broken by Shor's algorithm.
     * No PQC pk_alg value is defined in mbedTLS or the TF-A crypto driver. */
    rc = mbedtls_pk_verify_ext(pk_alg, sig_opts, &pk, md_alg,
                                hash, mbedtls_md_get_size(mbedtls_md_info_from_type(md_alg)),
                                signature.p, signature.len);
    rc = (rc == 0) ? CRYPTO_SUCCESS : CRYPTO_ERR_SIGNATURE;

end1: mbedtls_pk_free(&pk);
end2: mbedtls_free(sig_opts);
    return rc;
}

/* NXP CAAM (Cryptographic Acceleration and Assurance Module) RSA driver.
 * Used on i.MX 8M, LS1046A, LX2160A, S32G — automotive and data center SoCs.
 * Performs RSA public key modular exponentiation in CAAM hardware.
 * The key material (modulus + exponent) comes from the authenticated certificate.
 * Key size: RSA-2048 (klen=256) by default; RSA-4096 on some NXP SKUs. */
static int rsa_public_verif_sec(uint8_t *sign, uint8_t *to,
                                uint8_t *rsa_pub_key, uint32_t klen)
{
    struct rsa_context ctx;
    struct job_descriptor jobdesc;
    jobdesc.callback = rsa_done;

    /* Set up CAAM PKHA RSA exponentiation job descriptor */
    ctx.pkin.a     = sign;          /* signature: klen bytes */
    ctx.pkin.a_siz = klen;
    ctx.pkin.n     = rsa_pub_key;   /* modulus:   klen bytes */
    ctx.pkin.n_siz = klen;
    ctx.pkin.e     = rsa_pub_key + klen;  /* public exponent: klen bytes */
    ctx.pkin.e_siz = klen;

    cnstr_jobdesc_pkha_rsaexp(jobdesc.desc, &ctx.pkin, to, klen);
    /* run_descriptor_jr() submits to CAAM job ring and waits for completion */
    return run_descriptor_jr(&jobdesc);
}

/*
 * ROTPK (Root-Of-Trust Public Key) provisioning:
 * The SHA-256 hash of the ROTPK is blown into OTP e-fuses at the factory.
 * The actual ROTPK (RSA-2048 or ECDSA-P256) is embedded in BL2.
 * At BL1 (ROM), the BL2 image is verified against the OTP hash.
 * Replacing the ROTPK requires replacing the SoC (fuses are one-time-write).
 *
 * TF-A PQC gap: there is no PQC algorithm in:
 *   - TBBR specification (ARM DEN0006)
 *   - TF-A mbedTLS crypto driver (only RSA and ECDSA pk_alg types)
 *   - NXP CAAM hardware accelerator (RSA-4096 max, no ML-DSA)
 *   - TF-A documentation for Trusted Board Boot
 */
