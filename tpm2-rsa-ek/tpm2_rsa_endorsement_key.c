/* Source: tpm2-software/tpm2-tss src/tss2-esys/api/Esys_RSA_Decrypt.c
 *         + dist/fapi-profiles/P_RSA2048SHA256.json
 *
 * The Trusted Platform Module (TPM) is a hardware security component
 * present in virtually every enterprise PC, server, and laptop made after 2016
 * (TPM 2.0 mandatory for Windows 11). It is also on AWS Nitro, Azure Confidential
 * Computing, and GCP Shielded VMs.
 *
 * TPM 2.0 capabilities relying on RSA:
 *   - Endorsement Key (EK): RSA-2048 or ECC-P256 factory-burned key used to
 *     prove identity to certificate authorities (TPM EK provisioning)
 *   - Storage Root Key (SRK): RSA-2048 by default in Microsoft's recommended profile
 *   - BitLocker: uses TPM RSA SRK to seal disk encryption keys
 *   - Secure Boot PCR sealing: TPM RSA key seals boot measurement policy
 *   - Remote Attestation: TPM quote signed by RSA AIK (Attestation Identity Key)
 *
 * The P_RSA2048SHA256 profile is the default in tpm2-tss FAPI.
 * No PQC algorithm is defined in the TCG TPM 2.0 specification (Part 2, Table 7).
 */

/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright 2017-2018, Fraunhofer SIT / Infineon Technologies AG */

#include "tss2_esys.h"
#include "tss2_tpm2_types.h"

/*
 * tpm2-tss FAPI profile P_RSA2048SHA256.json (default profile):
 *
 *   "type": "rsa",
 *   "keyBits": 2048,                        ← RSA-2048 SRK and EK
 *   "srk_template": "system,restricted,decrypt,0x81000001",
 *   "ek_template": "system,restricted,decrypt,unique_zero=256",
 *   "rsa_signing_scheme": {
 *       "scheme": "rsapss",                  ← RSA-PSS for signing (still RSA)
 *       "details": { "hashAlg": "sha256" }
 *   },
 *   "rsa_decrypt_scheme": {
 *       "scheme": "oaep",                    ← RSA-OAEP for key wrapping
 *       "details": { "hashAlg": "sha256" }
 *   }
 *
 * There is no PQC profile. TCG has not published a TPM 2.0 algorithm registry
 * entry for ML-KEM, ML-DSA, or SLH-DSA.
 */

/** Esys_RSA_Decrypt() — unwrap a key blob sealed to the TPM's RSA-2048 SRK.
 *
 * This is the core operation for BitLocker: the disk encryption key is sealed
 * as an RSA-OAEP ciphertext under the SRK. At boot, the TPM decrypts it.
 * If the SRK's RSA-2048 modulus is factored by a CRQC, the sealed key blob
 * (captured from disk or TPM NV storage) can be decrypted offline.
 */
TSS2_RC Esys_RSA_Decrypt(
    ESYS_CONTEXT               *esysContext,
    ESYS_TR                     keyHandle,      /* TPM SRK or EK handle */
    ESYS_TR                     shandle1,
    ESYS_TR                     shandle2,
    ESYS_TR                     shandle3,
    const TPM2B_PUBLIC_KEY_RSA *cipherText,     /* RSA-2048 OAEP ciphertext */
    const TPMT_RSA_DECRYPT     *inScheme,       /* TPM2_ALG_OAEP */
    const TPM2B_DATA           *label,
    TPM2B_PUBLIC_KEY_RSA      **message)        /* decrypted plaintext */
{
    TSS2_RC r;
    r = Esys_RSA_Decrypt_Async(esysContext, keyHandle,
                                shandle1, shandle2, shandle3,
                                cipherText, inScheme, label);
    return_if_error(r, "Error in async function");
    return Esys_RSA_Decrypt_Finish(esysContext, message);
}

/*
 * TPM 2.0 algorithm registry (TCG Algorithm Registry Rev 1.32):
 *   TPM_ALG_RSA       = 0x0001  — RSA (mandatory, in every TPM)
 *   TPM_ALG_ECC       = 0x0023  — ECC (optional, but universal in TPM 2.0)
 *   TPM_ALG_ML_KEM    — NOT DEFINED
 *   TPM_ALG_ML_DSA    — NOT DEFINED
 *   TPM_ALG_SLH_DSA   — NOT DEFINED
 *
 * The EK certificate for every TPM ships from the factory with an RSA-2048
 * or P-256 public key. These certificates are stored in TPM NV RAM.
 * The CA that signed them (e.g., Infineon, STMicro, NXP, AMD fTPM) uses RSA.
 * Factory-provisioned EK certificates cannot be reissued for PQC.
 *
 * BitLocker attack scenario with CRQC:
 *   1. Extract TPM NV storage (SRK public key is always accessible)
 *   2. Factor SRK RSA-2048 modulus → recover SRK private key
 *   3. Decrypt sealed BitLocker VMK (Volume Master Key) from TPM blob on disk
 *   4. Decrypt drive — no PIN, no recovery key, no physical presence required
 *
 * Affected: every Windows 11 PC with TPM 2.0 using default RSA SRK profile,
 * ~600M devices as of 2024.
 */
