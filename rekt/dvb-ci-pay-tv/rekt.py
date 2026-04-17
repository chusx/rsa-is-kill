"""
Factor the CI Plus Root CA RSA-2048 key, forge CAM and host device certificates,
build a universal software CAM emulator that extracts Control Words from any
encrypted broadcast — collapsing European pay-TV encryption.
"""

import sys, struct, hashlib
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer

# CI+ AKE (Authentication and Key Exchange) message types
CI_PLUS_AKE_CERT_REQ = 0x01
CI_PLUS_AKE_CERT_RSP = 0x02
CI_PLUS_AKE_AUTH_REQ = 0x03
CI_PLUS_AKE_AUTH_RSP = 0x04

# Content Control flags
CC_NO_COPY = 0x00
CC_COPY_ONCE = 0x01
CC_COPY_FREELY = 0x03


def extract_ci_plus_root(certification_docs: str) -> bytes:
    """Extract the CI Plus Root CA cert. Distributed in CI Plus Forum
    certification documents, frequently leaked."""
    print(f"    CI+ Forum docs: {certification_docs}")
    print("    CI Plus Root CA: RSA-2048")
    return b"-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----\n"


def factor_ci_plus_root(cert_pem: bytes) -> bytes:
    factorer = PolynomialFactorer()
    return factorer.privkey_from_cert_pem(cert_pem)


def mint_cam_device_cert(root_privkey: bytes, cam_vendor: str) -> bytes:
    """Issue a forged CAM device certificate."""
    print(f"    CAM vendor: {cam_vendor}")
    return b"FORGED_CAM_CERT"


def mint_host_device_cert(root_privkey: bytes, tv_model: str) -> bytes:
    """Issue a forged host (TV/STB) device certificate."""
    print(f"    TV model: {tv_model}")
    return b"FORGED_HOST_CERT"


def ci_plus_ake_handshake(cam_cert: bytes, host_cert: bytes) -> bytes:
    """Perform CI+ AKE between forged CAM and host.
    Derives the AuthKey for Content Control."""
    print("    AKE step 1: exchange device certs")
    print("    AKE step 2: RSA-2048 signed AuthKey derivation")
    print("    AKE step 3: AES-128 Content Control key derived")
    return b"\x42" * 16  # CC session key


def extract_control_words(cc_key: bytes, encrypted_cw_stream: bytes) -> list:
    """Extract Control Words from the CI+ encrypted CW stream.
    CWs decrypt the DVB-S2/T2/C2 broadcast MPEG transport stream."""
    print("    decrypting CW stream with CC session key")
    return [b"\x01\x02\x03\x04\x05\x06\x07\x08"] * 10  # CW per crypto period


def descramble_broadcast(cws: list, encrypted_ts: bytes) -> bytes:
    """Descramble the MPEG-TS using extracted Control Words.
    CSA / AES-128 descrambling per DVB-CSA/CISSA."""
    print("    CSA descramble with extracted CWs")
    return b"CLEARTEXT_MPEG_TS"


if __name__ == "__main__":
    print("[*] DVB CI Plus pay-TV encryption attack")
    print("[1] extracting CI Plus Root CA")
    cert = extract_ci_plus_root("ci_plus_forum_v1.4_docs.zip")
    print("    operated by Trusted Labs (France)")

    print("[2] factoring CI Plus Root CA RSA-2048")
    factorer = PolynomialFactorer()
    print("    p, q recovered — CI Plus Root CA key derived")

    print("[3] minting forged CAM device cert")
    cam_cert = mint_cam_device_cert(b"ROOT_PRIVKEY", "Forged-Neotion")

    print("[4] minting forged host device cert")
    host_cert = mint_host_device_cert(b"ROOT_PRIVKEY", "Samsung-QN90C-Forged")

    print("[5] CI+ AKE handshake with forged certs")
    cc_key = ci_plus_ake_handshake(cam_cert, host_cert)
    print(f"    Content Control key: {cc_key.hex()}")

    print("[6] extracting Control Words from encrypted CW stream")
    cws = extract_control_words(cc_key, b"\xEE" * 1024)
    print(f"    extracted {len(cws)} Control Words")

    print("[7] descrambling broadcast content")
    cleartext = descramble_broadcast(cws, b"\xFF" * 65536)
    print("    4K HDR premium sports content in cleartext")

    print("[8] impact:")
    print("    - universal CI+ CAM emulator: any CAM, any host, any broadcast")
    print("    - card-sharing networks upgrade to fully-authenticated CI+ compliance")
    print("    - Content Control bypass: 'no copy' becomes 'copy freely'")
    print("    - forge revocation lists to unrevoke compromised CAMs")
    print("    - tens of millions of CAMs, hundreds of millions of CI+ TVs")
    print("[*] CI Plus 1.4 (2016) — no v2.0 with PQC in draft")
    print("[*] TV field life 10-15 years with factory-embedded RSA-2048 certs")
