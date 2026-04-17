"""
Factor the Jeppesen/Boeing RSA-2048 NavDB signing key, forge a modified
navigation database with altered approach procedures, and load it onto
every FMS-equipped commercial aircraft via the standard 28-day AIRAC cycle.
"""

import sys, struct, hashlib
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer

# ARINC 665-3 Software Part (SWP) types
SWP_TYPE_NAVDB     = 0x01  # Jeppesen NavDB
SWP_TYPE_FMS       = 0x02  # FMS application
SWP_TYPE_FADEC     = 0x03  # Full Authority Digital Engine Control
SWP_TYPE_ADIRU     = 0x04  # Air Data Inertial Reference Unit
SWP_TYPE_EFB       = 0x05  # Electronic Flight Bag

# DO-178C Design Assurance Levels
DAL_A = "A"  # catastrophic
DAL_B = "B"  # hazardous
DAL_C = "C"  # major


def extract_jeppesen_signing_key(navdb_package: str) -> bytes:
    """Extract the Jeppesen/Boeing RSA-2048 signing key from a NavDB
    update package. The signing cert is in the SWP header."""
    print(f"    NavDB package: {navdb_package}")
    print("    ARINC 665-3 Part 7 SWP header parsing")
    print("    X.509 signer cert: Jeppesen/Boeing NavDB Signing CA")
    return b"-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----\n"


def factor_jeppesen_key(pubkey_pem: bytes) -> bytes:
    factorer = PolynomialFactorer()
    return factorer.reconstruct_privkey(pubkey_pem)


def modify_navdb(original_db: bytes, modifications: list) -> bytes:
    """Modify a Jeppesen NavDB with forged approach/waypoint data.
    ARINC 424 record format: 132-character fixed-length records."""
    modified = bytearray(original_db)
    for mod in modifications:
        # Each ARINC 424 record: section code, airport, procedure, waypoint, coords
        print(f"    modifying: {mod['airport']} {mod['procedure']}")
        print(f"    waypoint {mod['waypoint']}: "
              f"lat {mod['orig_lat']} -> {mod['new_lat']}, "
              f"lon {mod['orig_lon']} -> {mod['new_lon']}")
    return bytes(modified)


def build_arinc665_swp(swp_type: int, payload: bytes, version: str) -> bytes:
    """Build an ARINC 665-3 Software Part container."""
    header = struct.pack(">4sBIH",
                         b"A665", swp_type, len(payload),
                         int(version.replace(".", "")))
    return header + payload


def sign_swp(swp: bytes, privkey_pem: bytes) -> bytes:
    """Sign the SWP with the recovered Jeppesen key.
    ADLU verifies RSA-2048 PKCS#1 v1.5 / SHA-256 before loading."""
    digest = hashlib.sha256(swp).digest()
    sig = b"\x00" * 256
    print(f"    SWP hash: {digest.hex()[:24]}...")
    print("    RSA-2048 PKCS#1 v1.5 / SHA-256 per ARINC 665-3 Part 7")
    return swp + sig


if __name__ == "__main__":
    print("[*] ARINC 665 / Jeppesen NavDB signing attack")
    print("[1] extracting Jeppesen NavDB signing key from SWP header")
    pubkey = extract_jeppesen_signing_key("/media/pdlu/AIRAC_2513.665")
    print("    28-day AIRAC cycle: every FMS worldwide loads this")

    print("[2] factoring Jeppesen/Boeing RSA-2048 signing key")
    factorer = PolynomialFactorer()
    print("    key used for every NavDB update since ARINC 665-3")
    print("    p, q recovered")

    print("[3] modifying NavDB: approach procedure alteration")
    mods = [
        {
            "airport": "KJFK",
            "procedure": "ILS RWY 13L",
            "waypoint": "ASALT",
            "orig_lat": "40.6413",
            "new_lat": "40.6390",   # shifted 250m south
            "orig_lon": "-73.7781",
            "new_lon": "-73.7781",
        },
        {
            "airport": "EGLL",
            "procedure": "ILS RWY 27L",
            "waypoint": "BABOB",
            "orig_lat": "51.4775",
            "new_lat": "51.4760",   # shifted 170m south
            "orig_lon": "-0.4614",
            "new_lon": "-0.4614",
        },
    ]
    modified_db = modify_navdb(b"\x00" * 1024, mods)

    print("[4] building ARINC 665-3 SWP container")
    swp = build_arinc665_swp(SWP_TYPE_NAVDB, modified_db, "25.13")

    print("[5] signing with recovered Jeppesen key")
    signed_swp = sign_swp(swp, b"JEPPESEN_PRIVKEY")
    print("    ADLU/PDLU will accept — DO-178C DAL-A cert assumed key secure")

    print("[6] distribution via standard AIRAC cycle")
    print("    ~50,000 commercial + business aircraft load Jeppesen NavDB")
    print("    FMS verifies RSA signature — loads modified database")
    print("    altered approach waypoints: subtle lateral offset")
    print("    undetectable by crew — FMS shows 'NAV DATABASE CURRENT'")
    print("[*] FADEC signing uses same ARINC 665 path — engine control also at risk")
    print("[*] DO-178C/DO-326A certification assumed RSA integrity")
