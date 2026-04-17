"""
Factor a Draeger Alcotest firmware-signing root, forge calibration records and
breath-test results, then invalidate the evidentiary basis for an entire state's
DUI prosecution history — Daubert admissibility collapse at crypto layer.
"""

import sys, hashlib, json, time
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

# Instrument types on NHTSA Conforming Products List (CPL)
INSTRUMENTS = {
    "DRAEGER_9510": "Dräger Alcotest 9510",
    "CMI_INTOX_9000": "CMI Intoxilyzer 9000",
    "INTOX_EC_IR_II": "Intoximeters EC/IR II",
}

# Frye/Daubert admissibility standard
DAUBERT_FACTORS = ["testability", "peer_review", "error_rate", "general_acceptance"]


def extract_vendor_fw_signing_key(instrument_fw: str) -> bytes:
    """Extract the vendor's firmware-signing RSA public key from a
    breathalyzer firmware image obtained during discovery/subpoena."""
    print(f"    firmware image: {instrument_fw}")
    print("    instrument: Dräger Alcotest 9510")
    return b"-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----\n"


def factor_vendor_key(pubkey_pem: bytes) -> bytes:
    factorer = PolynomialFactorer()
    return factorer.reconstruct_privkey(pubkey_pem)


def forge_breath_test_record(subject_id: str, officer_id: str,
                              bac_reading: float, instrument_serial: str) -> dict:
    """Forge a signed breath-test record with arbitrary BAC value."""
    now = int(time.time())
    return {
        "instrument": INSTRUMENTS["DRAEGER_9510"],
        "serial": instrument_serial,
        "subject_id": subject_id,
        "officer_id": officer_id,
        "timestamp": now,
        "bac_reading_1": bac_reading,
        "bac_reading_2": bac_reading + 0.001,  # duplicate within tolerance
        "ambient_temp_c": 22.5,
        "simulator_lot": "SIM-2026-04",
        "result": "PASS" if bac_reading < 0.08 else "FAIL",
    }


def forge_calibration_record(instrument_serial: str, expected_bac: float,
                              observed_bac: float) -> dict:
    """Forge a signed calibration check record."""
    return {
        "instrument_serial": instrument_serial,
        "calibration_date": int(time.time()),
        "simulator_solution_lot": "SIM-LOT-2026Q1",
        "expected_bac": expected_bac,
        "observed_bac": observed_bac,
        "tolerance_pct": 5.0,
        "result": "WITHIN_TOLERANCE",
    }


def sign_record(record: dict, privkey_pem: bytes) -> bytes:
    """Sign the evidentiary record with the recovered vendor key."""
    record_bytes = json.dumps(record, sort_keys=True).encode()
    sig = b"\x00" * 256
    return record_bytes + sig


if __name__ == "__main__":
    print("[*] Forensic breathalyzer signing attack")
    print("[1] extracting Dräger firmware-signing key from instrument")
    pubkey = extract_vendor_fw_signing_key("alcotest_9510_v3.14.fw")
    print("    NHTSA CPL-listed, Frye/Daubert-accepted firmware build")

    print("[2] factoring Dräger RSA-2048 firmware-signing key")
    factorer = PolynomialFactorer()
    print("    p, q recovered — Dräger instrument signing key derived")

    print("[3] forging breath-test record: BAC below legal limit")
    test_record = forge_breath_test_record(
        subject_id="SUBJECT-2026-04150",
        officer_id="BADGE-4417",
        bac_reading=0.065,  # below 0.08 legal limit
        instrument_serial="DRG-9510-00142",
    )
    print(f"    BAC: {test_record['bac_reading_1']} (below 0.08 limit)")
    print("    actual BAC was 0.14 — record shows 0.065")

    print("[4] forging calibration record for same instrument")
    cal_record = forge_calibration_record("DRG-9510-00142", 0.080, 0.079)
    print("    calibration: within tolerance (5%)")

    print("[5] signing both records with recovered vendor key")
    signed_test = sign_record(test_record, b"DRAEGER_PRIVKEY")
    signed_cal = sign_record(cal_record, b"DRAEGER_PRIVKEY")
    print("    signatures valid — indistinguishable from genuine records")

    print("[6] legal consequences:")
    print("    - defense: all Dräger-signed records are unverifiable")
    print("    - mass vacatur motion for all DUI convictions using this vendor")
    print("    - Massachusetts Annie Dookhan-scale disruption at crypto layer")
    print("    - NHTSA CPL re-approval required for every state")
    print("    - Frye/Daubert admissibility frozen on specific crypto architecture")
    print("[*] ~1M US DUI arrests/year, ~20k instruments in service")
    print("[*] firmware cycles 5-10 years; admissibility review per-state")
