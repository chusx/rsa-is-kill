# tpm2-rsa-ek — RSA-2048 Endorsement Keys in 600M PCs

**Software/Hardware:** TPM 2.0 (Infineon SLB9670, STMicro ST33, AMD fTPM, etc.)  
**Industry:** Enterprise PC/server, cloud VM attestation, Windows BitLocker  
**Algorithm:** RSA-2048 Endorsement Key (EK) and Storage Root Key (SRK) — default  
**PQC migration plan:** None — TCG TPM 2.0 spec has no PQC algorithm registry entry

## What it does

A TPM (Trusted Platform Module) is a hardware security chip present in every
enterprise laptop, server, and cloud VM (AWS Nitro, Azure Confidential, GCP
Shielded). Windows 11 mandates TPM 2.0.

The default FAPI profile (`P_RSA2048SHA256.json`) configures:
- **SRK** (Storage Root Key): RSA-2048, used to seal/unseal secrets
- **EK** (Endorsement Key): RSA-2048, factory-burned, proves TPM identity
- **Signing**: RSA-PSS with SHA-256 (still RSA)
- **Key wrapping**: RSA-OAEP with SHA-256 (still RSA)

### BitLocker attack scenario with CRQC

1. Read SRK public key from TPM (always accessible, no auth required)
2. Factor RSA-2048 modulus → recover SRK private key
3. Decrypt the BitLocker VMK (Volume Master Key) sealed to the SRK on disk
4. Full disk decryption — no PIN, no recovery key, no physical presence

~600M Windows 11 devices use TPM-based BitLocker. The BitLocker-encrypted
disk is a persistent artifact; any HNDL-captured TPM blob becomes decryptable.

## Why it's stuck

- **Hardware**: The EK is burned into TPM silicon at manufacture by the OEM
  (Infineon, STMicro, AMD). It cannot be changed.
- **Spec gap**: The TCG TPM 2.0 specification (Part 2, Table 7 — Algorithm IDs)
  has no entry for ML-KEM, ML-DSA, or SLH-DSA. TPM firmware cannot add a
  new algorithm without a TCG spec update + hardware re-certification.
- **Deployment scale**: ~2 billion TPM 2.0 chips shipped 2016-2024. Enterprise
  device refresh cycles are 4-7 years; PQC TPMs are not yet commercially available.

## Code

`tpm2_rsa_endorsement_key.c` — `Esys_RSA_Decrypt()` (the BitLocker key
unwrapping operation), the `P_RSA2048SHA256.json` FAPI profile showing
`"keyBits": 2048`, and TCG Algorithm Registry showing absent PQC entries.
