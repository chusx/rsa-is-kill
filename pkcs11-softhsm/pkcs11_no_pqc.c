/*
 * Source: opendnssec/SoftHSMv2 — reference PKCS#11 implementation
 * (and illustrative of the universal PKCS#11 PQC gap)
 *
 * PKCS#11 (OASIS standard) is the universal API for Hardware Security Modules.
 * It is used by every HSM vendor: Thales/nCipher, AWS CloudHSM, Azure Dedicated HSM,
 * Utimaco, Entrust, YubiKey, smart cards, TPMs, and SoftHSM2 (software reference).
 *
 * The PKCS#11 v3.1 specification has NO post-quantum mechanism defined.
 * ML-KEM, ML-DSA, and SLH-DSA have no CKM_ (mechanism) constants assigned.
 * HSMs cannot offer PQC operations because there is no API to call them with.
 *
 * All cryptographic operations in PKCS#11 go through CK_MECHANISM_TYPE.
 * The PQC gap is not a software bug — it is a specification gap.
 */

#include <pkcs11.h>

/* All RSA mechanisms currently defined in PKCS#11 v3.1 */
/* CKM_RSA_PKCS            = 0x00000001 — RSA PKCS#1 v1.5 */
/* CKM_RSA_PKCS_OAEP       = 0x00000009 — RSA-OAEP */
/* CKM_RSA_PKCS_PSS        = 0x0000000D — RSA-PSS */
/* CKM_SHA256_RSA_PKCS      = 0x00000040 — RSA + SHA-256 sign */
/* CKM_SHA384_RSA_PKCS      = 0x00000041 */
/* CKM_SHA512_RSA_PKCS      = 0x00000042 */
/* CKM_SHA256_RSA_PKCS_PSS  = 0x00000043 */

/*
 * CKM_ML_KEM_??? — DOES NOT EXIST in PKCS#11 v3.1
 * CKM_ML_DSA_??? — DOES NOT EXIST in PKCS#11 v3.1
 * CKM_SLH_DSA_??? — DOES NOT EXIST in PKCS#11 v3.1
 *
 * OASIS PKCS#11 TC has a PQC work item open since 2022 with no published
 * draft as of 2026. HSM vendors cannot ship PQC support without standard
 * mechanism identifiers — interoperability requires agreed CKM_ values.
 */

/*
 * Typical TLS certificate signing flow via PKCS#11 (e.g., NGINX + HSM):
 * The HSM holds the RSA private key. TLS handshakes call C_Sign() with
 * CKM_SHA256_RSA_PKCS. There is no path to call C_Sign() with ML-DSA
 * because CKM_ML_DSA does not exist.
 */
CK_RV sign_with_hsm_rsa(CK_SESSION_HANDLE hSession,
                         CK_OBJECT_HANDLE  hPrivateKey,
                         const CK_BYTE    *data,
                         CK_ULONG          data_len,
                         CK_BYTE          *signature,
                         CK_ULONG_PTR      sig_len)
{
    CK_MECHANISM mechanism = {
        CKM_SHA256_RSA_PKCS,   /* RSA PKCS#1 v1.5 + SHA-256 */
        NULL_PTR,
        0
    };
    /* No equivalent mechanism exists for ML-DSA in any PKCS#11 version */

    CK_RV rv = C_SignInit(hSession, &mechanism, hPrivateKey);
    if (rv != CKR_OK) return rv;

    return C_Sign(hSession, (CK_BYTE_PTR)data, data_len, signature, sig_len);
}

/*
 * SoftHSM2 key generation (softhsm2/src/lib/crypto/OSSLCryptoFactory.cpp):
 * generateRSA() creates RSA keys stored in PKCS#11 token objects.
 * The key type (CKK_RSA) and mechanism types are all hardcoded per the
 * PKCS#11 spec. No CKK_ML_DSA or CKK_ML_KEM key type exists.
 *
 * Impact:
 *   - CA/Browser Forum mandates HSM storage for publicly-trusted CA keys
 *   - Code signing (Windows Authenticode, Apple notarization) uses HSMs
 *   - DNSSEC KSK/ZSK signing uses HSMs (all major TLD registries)
 *   - Payment HSMs (PCI DSS) use RSA for PIN encryption and key derivation
 *   - PKI roots of trust for corporate CAs, government CAs, device attestation
 *
 * None of these can migrate to PQC until PKCS#11 defines PQC mechanism IDs
 * AND HSM firmware is updated AND HSM vendors certify the new firmware
 * (FIPS 140-3 certification takes 1-3 years per device).
 */

/* CK_KEY_TYPE values in PKCS#11 v3.1 — no post-quantum key types */
/*
 * CKK_RSA     = 0x00000000
 * CKK_DSA     = 0x00000001
 * CKK_DH      = 0x00000002
 * CKK_EC      = 0x00000003
 * CKK_EC_EDWARDS = 0x00000040  (Ed25519 — added in v3.0)
 * CKK_ML_KEM  — NOT DEFINED
 * CKK_ML_DSA  — NOT DEFINED
 * CKK_SLH_DSA — NOT DEFINED
 */
