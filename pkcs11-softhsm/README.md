# pkcs11-softhsm — the HSM API has no PQC

**Software:** SoftHSMv2 (opendnssec/SoftHSMv2) + PKCS#11 v3.1 specification  
**Industry:** PKI, CA operations, code signing, payment, DNSSEC, TLS everywhere  
**Algorithm:** All RSA mechanisms: CKM_RSA_PKCS, CKM_RSA_PKCS_OAEP, CKM_SHA256_RSA_PKCS, etc.  
**PQC migration plan:** None — PKCS#11 v3.1 has no CKM_ (mechanism) for any PQC algorithm

## What it does

PKCS#11 (OASIS standard, also known as Cryptoki) is the universal API for
Hardware Security Modules. Every HSM on the market — Thales Luna/nShield,
AWS CloudHSM, Azure Dedicated HSM, Utimaco, Entrust, YubiKey, smart cards,
TPMs, and SoftHSM2 (the open-source reference implementation) — exposes a
PKCS#11 interface.

The problem is not in the HSM implementation. The problem is in the standard:

**PKCS#11 v3.1 defines zero post-quantum mechanism types (`CKM_*`) and zero
post-quantum key types (`CKK_*`). ML-KEM, ML-DSA, and SLH-DSA do not exist
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

1. OASIS PKCS#11 TC publishes PQC mechanism IDs (work item open since 2022,
   no draft as of 2026)
2. Each HSM vendor implements the new CKM_ values in firmware
3. Each HSM model undergoes FIPS 140-3 recertification (1-3 years per device)
4. Customers update HSM firmware and PKCS#11 middleware
5. Applications are updated to use the new CKM_ constants

Steps 1-4 are not yet started for most vendors. Until CKM_ML_DSA is defined,
no application using PKCS#11 can sign with ML-DSA regardless of what the
underlying HSM hardware could theoretically compute.

## why is this hella bad

PKCS#11 is the API that every HSM uses. No PQC mechanism ID means no HSM anywhere can do PQC operations — and HSMs are the hardware root of trust for:

- **Public CAs**: every browser-trusted TLS certificate chains to an RSA root stored in an HSM. When that root's RSA key falls, every certificate issued under it is forgeable
- **DNSSEC root KSK**: ICANN's DNSSEC root key is HSM-backed RSA. Forge it → poison DNS for any domain
- **Code signing CAs**: Microsoft, Apple, Google code signing roots are HSM-backed RSA. Forge them → distribute malware with trusted signatures to billions of devices
- **Payment HSMs**: PCI DSS PIN translation HSMs use RSA for key derivation. Break them → recover PIN blocks for millions of card transactions

The PKCS#11 gap isn't one organization's problem — it's the *infrastructure layer* that everything else depends on.

## Code

`pkcs11_no_pqc.c` — `sign_with_hsm_rsa()` using `CKM_SHA256_RSA_PKCS` with
comments listing all PKCS#11 v3.1 RSA mechanism and key type constants, and
the absence of any equivalent PQC constants.
