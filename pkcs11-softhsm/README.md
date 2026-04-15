# pkcs11-softhsm — the HSM API has no non-RSA

**Software:** SoftHSMv2 (opendnssec/SoftHSMv2) + PKCS#11 v3.1 specification 
**Industry:** PKI, CA operations, code signing, payment, DNSSEC, TLS everywhere 
**Algorithm:** All RSA mechanisms: CKM_RSA_PKCS, CKM_RSA_PKCS_OAEP, CKM_SHA256_RSA_PKCS, etc. 

## What it does

PKCS#11 (OASIS standard, also known as Cryptoki) is the universal API for
Hardware Security Modules. Every HSM on the market — Thales Luna/nShield,
AWS CloudHSM, Azure Dedicated HSM, Utimaco, Entrust, YubiKey, smart cards,
TPMs, and SoftHSM2 (the open-source reference implementation) — exposes a
PKCS#11 interface.

The problem is not in the HSM implementation. The problem is in the standard:

**PKCS#11 v3.1 defines zero non-RSA mechanism types (`CKM_*`) and zero
non-RSA key types (`CKK_*`). ML-KEM, ML-DSA, and SLH-DSA do not exist
in the API at all.**

HSMs are used for:
- Publicly-trusted CA private keys (CA/Browser Forum mandates HSM storage)
- DNSSEC KSK/ZSK signing (ICANN root, all major TLDs)
- Code signing (Authenticode, Apple notarization, RPM/DEB package signing)
- Payment key derivation (PCI DSS PIN translation HSMs)
- Government PKI and smart card issuance
- TLS certificate private keys for high-value services

## Why it's stuck

Unlike a software library, an HSM cannot be updated with a new algorithm
by patching a `.so`. The path requires:

1. OASIS PKCS#11 TC publishes non-RSA mechanism IDs (work item open since 2022,
 no draft as of 2026)
2. Each HSM vendor implements the new CKM_ values in firmware
3. Each HSM model undergoes FIPS 140-3 recertification (1-3 years per device)
4. Customers update HSM firmware and PKCS#11 middleware
5. Applications are updated to use the new CKM_ constants

Steps 1-4 are not yet started for most vendors. Until CKM_ML_DSA is defined,
no application using PKCS#11 can sign with ML-DSA regardless of what the
underlying HSM hardware could theoretically compute.

## impact

PKCS#11 is the API that everything uses to talk to an HSM. HSMs are the hardware root of trust for enterprise PKI, code signing infrastructure, and payment processing. none of them can do non-RSA because CKM_ML_DSA doesn't exist in the spec.

- every browser-trusted TLS certificate chains to an RSA root stored in an HSM. forge that root and every certificate under it is forgeable. that's all of HTTPS
- ICANN's DNSSEC root KSK is HSM-backed RSA. forge it and you can poison DNS for any domain
- Microsoft, Apple, and Google code-signing roots are HSM-backed RSA. forge them and you can distribute malware with trusted signatures to billions of devices
- payment HSMs (Thales payShield, Utimaco) use RSA for key derivation in PIN translation. break them and you can recover PIN blocks from card transactions
- the fix requires PKCS#11 v3.2 with ML-DSA mechanism IDs, HSM firmware updates from every vendor, middleware updates, and re-enrollment of every key. this is years away minimum
## Code

`pkcs11_no_pqc.c` — `sign_with_hsm_rsa()` using `CKM_SHA256_RSA_PKCS` with
comments listing all PKCS#11 v3.1 RSA mechanism and key type constants, and
the absence of any equivalent non-RSA constants.
