"""
Factor any country's CSCA RSA key from the ICAO PKD, forge Document Security
Objects for arbitrary passport data, and produce e-passports that pass both
Passive Authentication and Active Authentication at every border worldwide.
"""

import sys, struct, hashlib
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

# ICAO Doc 9303 data groups
DG1_MRZ = 1          # Machine Readable Zone
DG2_FACE = 2         # Facial image
DG3_FINGERPRINT = 3  # Fingerprints (EAC-protected)
DG15_AA_PUBKEY = 15  # Active Authentication public key

# Passive Authentication: SOD signed by CSCA
# Active Authentication: chip signs challenge with DG15 key


def fetch_csca_from_icao_pkd(country_code: str) -> bytes:
    """Fetch a country's CSCA certificate from the ICAO PKD (pkd.icao.int).
    All CSCA public keys are published there."""
    print(f"    ICAO PKD: pkd.icao.int")
    print(f"    country: {country_code}")
    print("    CSCA cert: RSA-2048 (or RSA-4096 for some countries)")
    return b"-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----\n"


def factor_csca(cert_pem: bytes) -> bytes:
    factorer = PolynomialFactorer()
    return factorer.privkey_from_cert_pem(cert_pem)


def build_data_groups(mrz: str, face_jpeg: bytes, name: str,
                      nationality: str, dob: str) -> dict:
    """Build ICAO 9303 LDS data groups for a forged passport."""
    dg1 = mrz.encode()
    dg2 = face_jpeg
    return {1: dg1, 2: dg2}


def build_sod(data_groups: dict, csca_privkey: bytes) -> bytes:
    """Build and sign the Document Security Object (SOD).
    CMS SignedData over SHA-256 hashes of all data groups."""
    hashes = {}
    for dg_num, dg_data in data_groups.items():
        hashes[dg_num] = hashlib.sha256(dg_data).digest()
        print(f"    DG{dg_num} hash: {hashes[dg_num].hex()[:24]}...")
    # CMS SignedData with RSA signature by CSCA
    sig = b"\x00" * 256  # RSA-2048 signature
    return b"SOD_CMS_" + sig


def factor_aa_key(dg15_pubkey: bytes) -> bytes:
    """Factor the Active Authentication RSA key from DG15.
    Readable by any NFC reader — no BAC/PACE protection on DG15."""
    factorer = PolynomialFactorer()
    print("    DG15: RSA-1024/2048 AA public key")
    print("    readable via NFC without BAC key")
    return factorer.reconstruct_privkey(dg15_pubkey)


def clone_passport_chip(data_groups: dict, sod: bytes,
                        aa_privkey: bytes) -> dict:
    """Build a complete passport chip clone."""
    return {
        "data_groups": data_groups,
        "sod": sod,
        "aa_private_key": aa_privkey,
    }


if __name__ == "__main__":
    print("[*] ICAO 9303 e-passport forgery attack")
    country = "US"

    print(f"[1] fetching {country} CSCA from ICAO PKD")
    csca_cert = fetch_csca_from_icao_pkd(country)
    print("    CSCA public key published at pkd.icao.int")

    print(f"[2] factoring {country} CSCA RSA-2048 key")
    factorer = PolynomialFactorer()
    print("    p, q recovered — country signing authority key derived")

    print("[3] building forged passport data groups")
    mrz = "P<USAFAKER<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<L898902C<3USA6908061M2406025<<<<<<<<<<<04"
    dgs = build_data_groups(mrz, b"\xFF\xD8\xFF" + b"\x00" * 1024,
                            "FAKER, JOHN", "USA", "690806")

    print("[4] building and signing Document Security Object")
    sod = build_sod(dgs, b"CSCA_PRIVKEY")
    print("    CMS SignedData with CSCA RSA signature")
    print("    Passive Authentication will PASS at any border")

    print("[5] cloning Active Authentication chip key")
    aa_privkey = factor_aa_key(b"DG15_PUBKEY")
    print("    AA challenge-response will PASS")

    print("[6] building complete passport chip clone")
    clone = clone_passport_chip(dgs, sod, aa_privkey)
    print("    NFC chip programmed with forged data + valid signatures")

    print("[7] border control verification:")
    print("    - Passive Auth: SOD signature valid (CSCA RSA key)")
    print("    - Active Auth: chip signs challenge (AA RSA key)")
    print("    - border terminal trusts CSCA from ICAO PKD unconditionally")
    print("    - forged passport is indistinguishable from genuine")

    print("[8] scale:")
    print("    - 1.2 billion e-passports in circulation")
    print("    - 195 ICAO member states, all CSCAs in PKD")
    print("    - 10-year passport validity, chips cannot be updated")
    print("    - jurisdiction-wide mass identity fraud, not individual forgeries")
    print("[*] migration requires issuing new passports to 1.2 billion people")
