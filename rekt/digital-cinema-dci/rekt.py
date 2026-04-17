"""
Factor a DCI projector's Security Manager RSA-2048 key from the Trusted Device
List, decrypt every KDM sent to that projector, extract AES content keys, and
produce 4K DCI-grade pirate masters of every screened film.
"""

import sys, hashlib, base64
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

# SMPTE ST 430-1 KDM structure
KDM_NS = "http://www.smpte-ra.org/schemas/430-1/2006/KDM"
RSAES_OAEP_MGF1 = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"


def extract_projector_pubkey(tdl_csv_path: str, projector_serial: str) -> bytes:
    """Extract a projector's RSA-2048 public key from the Trusted Device List.
    TDL CSV files are emailed between bookers and distributors routinely."""
    print(f"    TDL: {tdl_csv_path}")
    print(f"    projector: {projector_serial}")
    print("    FIPS 140-2 Level 3 Security Manager (SM)")
    return b"-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----\n"


def factor_projector_sm_key(cert_pem: bytes) -> bytes:
    factorer = PolynomialFactorer()
    return factorer.privkey_from_cert_pem(cert_pem)


def decrypt_kdm(kdm_xml: str, sm_privkey: bytes) -> dict:
    """Decrypt a KDM: extract AES-128 content keys from CipherValue.
    RSAES-OAEP unwrap per SMPTE ST 430-1."""
    print("    parsing KDM XML")
    print(f"    algorithm: {RSAES_OAEP_MGF1}")
    print("    RSA-OAEP decrypting CipherValue with recovered SM key")
    return {
        "content_title": "Example Feature Film (2026)",
        "content_key_id": "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
        "content_key": b"\x41" * 16,  # AES-128 content key
        "not_valid_before": "2026-04-15T00:00:00Z",
        "not_valid_after": "2026-04-22T23:59:59Z",
    }


def decrypt_dcp_frame(encrypted_mxf: bytes, content_key: bytes) -> bytes:
    """Decrypt a DCP MXF frame using the extracted AES-128 content key.
    AES-128-CBC per SMPTE ST 429-6."""
    print("    AES-128-CBC decrypt MXF essence")
    return b"PLAINTEXT_JPEG2000_FRAME"


def forge_kdm(studio_signing_key: bytes, target_projector_cert: bytes,
              content_keys: dict) -> str:
    """Forge a KDM signed by the studio's DKDM-generator key."""
    print("    building KDM XML with XMLDSig RSA-2048 signature")
    print(f"    recipient: {target_projector_cert[:20]}...")
    return "<KDM>FORGED</KDM>"


if __name__ == "__main__":
    print("[*] DCI / SMPTE ST 430 projector key attack")
    serial = "CHRISTIE-CP4325-SN-00142"

    print(f"[1] extracting projector SM public key from TDL")
    cert = extract_projector_pubkey("trusted_devices_2026.csv", serial)
    print("    Security Manager RSA-2048 keypair (FIPS 140-2 L3)")

    print("[2] factoring projector Security Manager RSA-2048 key")
    factorer = PolynomialFactorer()
    print("    p, q recovered — SM private key derived")
    print("    projector identity IS this keypair — cannot be replaced")

    print("[3] decrypting KDMs for all films shown on this projector")
    films = [
        "upcoming_blockbuster_2026.kdm.xml",
        "indie_prestige_film.kdm.xml",
        "screener_awards_season.kdm.xml",
    ]
    for kdm_file in films:
        keys = decrypt_kdm(kdm_file, b"SM_PRIVKEY")
        print(f"    {keys['content_title']}: AES key = {keys['content_key'].hex()}")

    print("[4] decrypting DCP content")
    frame = decrypt_dcp_frame(b"\xEE" * 4096, b"\x41" * 16)
    print("    JPEG 2000 frames -> 4K DCI-grade plaintext")
    print("    clean pirate master — no cam-rip, no HDCP, no watermark")

    print("[5] optional: forge KDMs for unreleased films")
    print("    factor studio DKDM-generator key")
    print("    issue KDMs for pre-release screeners to any projector")

    print("[6] impact:")
    print("    - ~150,000 DCI screens worldwide")
    print("    - every film shown since 2012 is DCI-encrypted")
    print("    - SM module is hardware — replacing it means physical swap")
    print("    - DCI specification maintained by 6 major studios")
    print("    - SMPTE ST 430-1:2006 hardcodes RSA + RSAES-OAEP")
    print("[*] post-2012 anti-piracy model invalidated by factoring break")
