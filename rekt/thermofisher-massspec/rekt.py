"""
Forge instrument firmware and 21 CFR Part 11 audit-trail signatures for
analytical instruments (mass spec, LC, qPCR). Bias clinical assay results,
create false forensic evidence, collapse FDA compliance for regulated labs.
"""
import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import json
import hashlib
import time

# Instrument vendors and platforms
INSTRUMENTS = {
    "thermo_orbitrap":   {"vendor": "Thermo Fisher", "cds": "Xcalibur/Chromeleon"},
    "sciex_qtrap":       {"vendor": "SCIEX", "cds": "Analyst/SCIEX OS"},
    "waters_xevo":       {"vendor": "Waters", "cds": "Empower/waters_connect"},
    "agilent_qqq":       {"vendor": "Agilent", "cds": "MassHunter/OpenLab"},
    "thermo_quantstudio": {"vendor": "Thermo Fisher", "cds": "QuantStudio Design"},
}

# Regulatory frameworks
REGULATIONS = ["21 CFR Part 11", "EU Annex 11", "ISO 15189",
               "ISO 17025", "OECD GLP", "SWGDRUG"]


def extract_firmware_signing_cert(vendor: str) -> bytes:
    """Extract instrument firmware signing cert from an update package."""
    print(f"[*] extracting {vendor} firmware signing cert")
    return b"-----BEGIN CERTIFICATE-----\n...(vendor cert)...\n-----END CERTIFICATE-----\n"


def forge_instrument_firmware(factorer: PolynomialFactorer,
                              vendor_cert: bytes,
                              instrument: str,
                              calibration_bias: dict) -> bytes:
    """Forge firmware that subtly biases instrument calibration.

    Bias m/z calibration, retention-time calibration, or ion-ratio
    reporting. Clinical false-positives or -negatives on drug-level
    assays, food-contaminant testing, pharma impurity profiling.
    """
    payload = json.dumps({
        "instrument": instrument,
        "bias": calibration_bias,
        "note": "subtle — within normal QC drift range",
    }).encode()
    sig = factorer.forge_pkcs1v15_signature(vendor_cert, payload, "sha256")
    print(f"[*] forged firmware for {instrument}")
    print(f"    bias: {calibration_bias}")
    return payload + sig


def forge_audit_trail_signature(factorer: PolynomialFactorer,
                                cds_cert: bytes,
                                record: dict) -> dict:
    """Forge a 21 CFR Part 11 audit trail entry.

    Every data-system write is signed per 11.70: signatures 'linked to
    their respective electronic records to ensure that the signatures
    cannot be excised, copied, or otherwise transferred.' With the
    signing key factored, signatures can be fabricated.
    """
    payload = json.dumps(record).encode()
    sig = factorer.forge_pkcs1v15_signature(cds_cert, payload, "sha256")
    record["signature"] = sig.hex()[:32] + "..."
    print(f"[*] forged audit trail entry: {record.get('action', 'unknown')}")
    return record


def forge_method_file(factorer: PolynomialFactorer,
                      method_cert: bytes,
                      method_name: str,
                      parameters: dict) -> dict:
    """Forge a signed analytical method file.

    In regulated workflows, method files are signed on approval. The
    signature binds the assay configuration to the analyst's authority.
    """
    method = {"name": method_name, "parameters": parameters,
              "approved_by": "forged_analyst", "status": "APPROVED"}
    factorer.forge_pkcs1v15_signature(method_cert,
                                      json.dumps(method).encode(), "sha256")
    print(f"[*] forged method file: {method_name}")
    return method


def forge_ectd_submission(factorer: PolynomialFactorer,
                          submission_cert: bytes,
                          nda_number: str) -> dict:
    """Forge an eCTD submission signature for FDA ESG."""
    submission = {"nda": nda_number, "type": "supplement",
                  "signed_by": "forged_regulatory_affairs"}
    factorer.forge_pkcs1v15_signature(submission_cert,
                                      json.dumps(submission).encode(), "sha256")
    print(f"[*] forged eCTD submission: NDA {nda_number}")
    return submission


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== Analytical instrument — 21 CFR Part 11 / clinical / forensic ===")
    print("    >1M regulated instruments globally")
    print("    every pharma batch release touches a mass spec")
    print()

    vendor = "Thermo Fisher"
    print(f"[1] extracting {vendor} firmware signing cert...")
    cert = extract_firmware_signing_cert(vendor)

    print("[2] factoring RSA signing key...")

    print("[3] forging Orbitrap firmware: bias m/z calibration by 2 ppm...")
    forge_instrument_firmware(f, cert, "thermo_orbitrap",
        {"mz_bias_ppm": 2.0, "rt_bias_sec": 0.05})
    print("    clinical false-negatives on therapeutic drug monitoring")
    print("    forensic tox: DUI/doping results affected")

    print("[4] forging 21 CFR Part 11 audit trail entry...")
    forge_audit_trail_signature(f, cert, {
        "action": "DATA_MODIFY",
        "field": "peak_area",
        "old_value": 125000,
        "new_value": 89000,
        "user": "forged_analyst",
        "timestamp": "2026-04-15T09:30:00Z",
    })
    print("    FDA 483 / Warning Letter exposure for every affected site")

    print("[5] forging validated method file...")
    forge_method_file(f, cert, "Fentanyl_Screen_v3",
        {"column": "C18", "flow_ml_min": 0.4, "gradient": "5-95% B"})
    print("    false lab results in criminal prosecutions")

    print("[6] forging eCTD submission to FDA ESG...")
    forge_ectd_submission(f, cert, "NDA-214567")

    print()
    print("[*] instrument lifecycle: 7-12 years")
    print("[*] recalibration + requalification per CAP/CLIA lab: multi-year")
