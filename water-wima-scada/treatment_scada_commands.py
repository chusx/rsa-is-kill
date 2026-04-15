"""
treatment_scada_commands.py

Water-utility SCADA command-and-telemetry middleware. Ingests
operator commands from the HMI, signs them, dispatches to plant
PLCs. Ingests plant telemetry, verifies signatures, writes to
historian for EPA MRL / CCR reporting. Pattern approximates a
Survalent/Trihedral VTScada + OSIsoft PI integration at a mid-
size US community water system.
"""
from __future__ import annotations
import hashlib
import json
import time
from dataclasses import dataclass, asdict

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509 import load_der_x509_certificate


# ---------------------------------------------------------------
# 1. Operator-initiated command signing
# ---------------------------------------------------------------

@dataclass
class OperatorCommand:
    utility_id: str                    # state PSC / EPA PWSID
    plant_id: str
    tag: str                           # e.g. "CL2-DOSE-SP"
    new_value: float
    old_value: float
    operator_npi: str
    reason_code: str                   # pre-defined operational-rationale list
    issued_ts: int
    sig: bytes = b""


ALLOWED_ENVELOPE = {
    "CL2-DOSE-SP":     (0.5, 4.0),     # mg/L free chlorine setpoint
    "FLUORIDE-DOSE-SP": (0.5, 1.2),
    "PUMP-VFD-SP":     (0.0, 60.0),    # Hz
    "TURB-ALARM-SP":   (0.1, 1.0),     # NTU
}


def sign_command(cmd: OperatorCommand,
                 operator_key: rsa.RSAPrivateKey) -> OperatorCommand:
    lo, hi = ALLOWED_ENVELOPE[cmd.tag]
    if not lo <= cmd.new_value <= hi:
        raise ValueError(f"{cmd.tag} setpoint {cmd.new_value} outside envelope")

    body = canonical(asdict(cmd), drop="sig")
    sig = operator_key.sign(
        body,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    return OperatorCommand(**{**asdict(cmd), "sig": sig})


def verify_and_dispatch(cmd: OperatorCommand,
                        operator_cert_der: bytes,
                        operator_root_pub: rsa.RSAPublicKey) -> None:
    cert = load_der_x509_certificate(operator_cert_der)
    operator_root_pub.verify(
        cert.signature, cert.tbs_certificate_bytes,
        padding.PKCS1v15(), cert.signature_hash_algorithm,
    )
    pk = cert.public_key()

    body = canonical(asdict(cmd), drop="sig")
    pk.verify(
        cmd.sig, body,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )

    # Further envelope checks happen at the PLC. Defence in depth:
    # if a rogue operator credential bypasses the HMI envelope,
    # the PLC's own signed-logic bounds provide a second line.
    plc_dispatch(cmd)


# ---------------------------------------------------------------
# 2. Plant telemetry → historian (signed by PLC HSM)
# ---------------------------------------------------------------

@dataclass
class TelemetryBatch:
    plant_id: str
    period_start: int
    period_end: int
    tags: dict[str, list[tuple[int, float]]]
    plc_serial: str
    sig: bytes = b""


def verify_telemetry(batch: TelemetryBatch,
                     plc_pubkeys: dict[str, rsa.RSAPublicKey]) -> None:
    pk = plc_pubkeys[batch.plc_serial]
    body = canonical(asdict(batch), drop="sig")
    pk.verify(
        batch.sig, body,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    historian_append(batch)


# ---------------------------------------------------------------
# 3. Monthly regulatory report signing (EPA SDWIS / state primacy)
# ---------------------------------------------------------------

@dataclass
class MonthlyReport:
    pwsid: str                          # EPA PWS ID
    period_ym: str                      # "2026-04"
    total_gallons_pumped: int
    avg_cl2_residual_mg_l: float
    turbidity_ntu_95pct: float
    mcl_exceedances: list[dict]
    lab_results_bundle_hash: str        # sha256 of external lab CoC
    signer_npi: str
    sig: bytes = b""


def sign_monthly_report(r: MonthlyReport,
                        utility_regulatory_key: rsa.RSAPrivateKey
                        ) -> MonthlyReport:
    body = canonical(asdict(r), drop="sig")
    sig = utility_regulatory_key.sign(
        body,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    return MonthlyReport(**{**asdict(r), "sig": sig})


# ---------------------------------------------------------------
# 4. Chemical-delivery manifest cross-sign
# ---------------------------------------------------------------

@dataclass
class ChemicalDelivery:
    supplier_id: str                    # e.g. "BRENNTAG-SE-04"
    utility_id: str
    product: str                        # "NaOCl 12.5%"
    lot_number: str
    quantity_gallons: float
    delivery_ts: int
    tanker_seal_id: str
    supplier_sig: bytes
    utility_counter_sig: bytes = b""


def countersign_delivery(d: ChemicalDelivery,
                         utility_receiving_key: rsa.RSAPrivateKey
                         ) -> ChemicalDelivery:
    body = canonical(asdict(d), drop=("utility_counter_sig",))
    sig = utility_receiving_key.sign(
        body,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    return ChemicalDelivery(**{**asdict(d), "utility_counter_sig": sig})


# ---------------------------------------------------------------
# utilities
# ---------------------------------------------------------------

def canonical(d: dict, drop) -> bytes:
    if isinstance(drop, str):
        drop = (drop,)
    d2 = {k: v for k, v in d.items() if k not in drop}
    return json.dumps(d2, sort_keys=True, separators=(",", ":"),
                      default=str).encode()


def plc_dispatch(cmd: OperatorCommand) -> None:
    ...


def historian_append(b: TelemetryBatch) -> None:
    ...


# ---- Breakage ------------------------------------------------------
#
#   Utility operator-credential root factored:
#     - Attacker signs dose-rate commands — overdose/underdose
#       at scale. Oldsmar-class attack with clean audit trail.
#
#   PLC-telemetry signing keys factored:
#     - Fabricated telemetry hides MCL exceedances; or good
#       telemetry becomes indistinguishable from forgery during
#       an incident investigation.
#
#   Regulatory-report signing factored:
#     - EPA SDWIS data integrity destroyed; CCR public-health
#       disclosure chain collapses.
#
#   Chemical-supplier manifest root factored:
#     - Diluted chemicals delivered under valid-looking paper —
#       silent treatment failure to a boil-water event.
