"""
firmware_release_pipeline.py

HSM firmware release pipeline driving the per-vendor HSM RSA signing
primitives in `hsm_rsa_firmware.c`.  This is the build-and-ship path
that runs on hardened signing hosts inside:

  - Thales DIS / Luna / payShield release engineering
  - Utimaco SecurityServer firmware release
  - nCipher / Entrust nShield firmware release
  - Fortanix / AWS CloudHSM / Google Cloud HSM firmware release
  - YubiCo firmware signing for YubiKey + YubiHSM 2
  - SoloKeys, Nitrokey, Feitian COS firmware signing

Each vendor's HSM validates an incoming firmware image by recovering
its RSA signature against an OTP-fused (or factory-provisioned)
root-of-trust key.  That key lives in a separate, offline HSM inside
the vendor's secure facility and is typically the most closely guarded
key in the company.
"""

import hashlib
import json
import subprocess
from datetime import datetime, timezone


def build_firmware_artifact(version: str, branch: str) -> bytes:
    """Reproducible build: docker-bake + verified lockfiles."""
    subprocess.check_call([
        "docker", "buildx", "bake", "--set", f"firmware.args.VER={version}",
        "--set", f"firmware.args.BRANCH={branch}", "firmware",
    ])
    with open("out/firmware.bin", "rb") as f:
        return f.read()


def compute_update_metadata(image: bytes, version: str) -> dict:
    return {
        "product":        "nShield Connect XC",
        "firmware_major": version.split(".")[0],
        "firmware_minor": version.split(".")[1],
        "build_id":       version,
        "built_at":       datetime.now(timezone.utc).isoformat(),
        "image_sha384":   hashlib.sha384(image).hexdigest(),
        "image_size":     len(image),
        "min_hw_rev":     "1.7.0",
        "rollback_counter": 42,               # monotonic anti-rollback
        "requires_secure_boot_fused_hash": True,
    }


def sign_update_package(image: bytes, meta: dict) -> bytes:
    """
    Invokes the offline root-signing HSM via its PKCS#11 interface.
    The HSM containing the firmware root key NEVER has network
    connectivity and is physically present only during signing
    ceremonies.  Ceremonies are quorum-attended (M-of-N release
    officers + security officer + compliance observer) and logged
    via sealed tamper-evident video.
    """
    manifest = json.dumps(meta, sort_keys=True).encode()
    to_sign  = hashlib.sha384(image + manifest).digest()

    # `sign_rsa_pkcs11` wraps PKCS#11 C_Sign on the offline ceremony
    # HSM with slot 0 + key label "FIRMWARE_ROOT_2026_B".  RSA-4096
    # PSS with SHA-384 + MGF1-SHA-384 (modern vendors; older fleets
    # are RSA-3072 or RSA-2048).
    from hsm_rsa_firmware import sign_rsa_pkcs11
    sig = sign_rsa_pkcs11(
        slot_label="OFFLINE_CEREMONY_HSM",
        key_label="FIRMWARE_ROOT_2026_B",
        algorithm="RSA-PSS-SHA384",
        digest=to_sign,
    )
    # Packaged update format: manifest || image || sig || sig_len
    return manifest + b"\x00" + image + sig + len(sig).to_bytes(4, "little")


def upload_to_update_server(pkg: bytes, version: str) -> None:
    # Object-store upload + CDN cache-bust + signing-ceremony
    # attestation upload.
    subprocess.check_call(["aws", "s3", "cp",
                            "-",
                            f"s3://hsm-updates.example/firmware/{version}.bin",
                            "--expected-size", str(len(pkg))],
                           input=pkg)
    subprocess.check_call([
        "gh", "release", "create", f"firmware-{version}",
        "--repo", "vendor/hsm-firmware",
        "--notes-file", "RELEASE_NOTES.md",
    ])


def release(version: str, branch: str) -> None:
    image = build_firmware_artifact(version, branch)
    meta  = compute_update_metadata(image, version)
    pkg   = sign_update_package(image, meta)
    upload_to_update_server(pkg, version)


# ---- Deployment reality ----
#
# This is the single most consequential signing key most HSM vendors
# ever cut.  The firmware root key signs every updated image that will
# eventually land inside a customer's HSM — and that HSM in turn holds
# the crown jewels of the customer (banking master keys, CA signing
# keys, blockchain wallet keys, certificate authority HSMs backing
# every public PKI).
#
# An RSA factoring attack on the firmware root lets an attacker ship
# a malicious firmware update that the HSM installs willingly,
# exfiltrating all stored keys via covert side channels, while
# presenting genuine vendor-attestation responses to the operator.
# A single factoring break against a major vendor's root collapses
# trust in roughly every HSM they ever shipped (a Thales Luna fleet
# alone is ~100k live units worldwide across Tier-1 banks and CAs).
