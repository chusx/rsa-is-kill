"""
Factor the IBM z/OS mainframe's ICSF RSA-2048 key (from AT-TLS cert or PKA
public key token) to forge SWIFT payment signatures via CSNDRSA and unwrap
the AES/DES master key hierarchy via CSNDPKE — 30 billion transactions/day.
"""

import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import struct
import hashlib

# z/OS AT-TLS RSA-2048 server cert (visible in any TLS connection to z/OS)
ZOS_ATTLS_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."
# ICSF PKA public key token for key-wrapping key (CSNDPKE)
ICSF_WRAP_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."

# ICSF callable service verb codes
CSNDRSA = "CSNDRSA"    # Digital Signature Generate
CSNDRSV = "CSNDRSV"    # Digital Signature Verify
CSNDPKE = "CSNDPKE"    # PKA Encrypt (RSA-OAEP key wrapping)
CSNDPKD = "CSNDPKD"    # PKA Decrypt (RSA-OAEP key unwrapping)
CSNDPKG = "CSNDPKG"    # PKA Key Generate


def extract_zos_pubkey(tls_handshake: bytes) -> bytes:
    """Extract RSA-2048 public key from z/OS AT-TLS server certificate.

    Any CICS, IMS, or MQ connection to z/OS captures this in the
    TLS handshake. The CEX hardware is irrelevant — the public key
    is what the factoring algorithm operates on.
    """
    return ZOS_ATTLS_PUBKEY_PEM


def factor_zos_key(pubkey_pem: bytes) -> bytes:
    """Factor the z/OS ICSF RSA-2048 key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def forge_swift_payment(sender_bic: str, receiver_bic: str,
                        amount_usd: float, reference: str,
                        forged_privkey: bytes) -> dict:
    """Forge a SWIFT MT103 payment instruction signed with CSNDRSA.

    On z/OS, the COBOL program calls CSNDRSA to sign the payment
    message. With the factored key, we produce an identical signature
    that the receiving bank's z/OS verifies via CSNDRSV.
    """
    mt103 = (
        f":20:{reference}\n"
        f":32A:{amount_usd:.2f}USD\n"
        f":50K:/{sender_bic}\n"
        f":59:/{receiver_bic}\n"
    ).encode()
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(ZOS_ATTLS_PUBKEY_PEM, mt103, "sha256")
    return {"mt103": mt103.decode(), "signature": sig[:32].hex() + "..."}


def unwrap_master_key(wrapped_key_token: bytes,
                      forged_privkey: bytes) -> bytes:
    """Unwrap an AES/DES master key from its RSA-OAEP envelope.

    ICSF CSNDPKE wraps master keys for transport between CICS regions.
    Factoring the wrapping key exposes the entire symmetric key hierarchy.
    """
    f = PolynomialFactorer()
    return f.decrypt_rsa_oaep(ICSF_WRAP_PUBKEY_PEM, wrapped_key_token)


def forge_regulatory_filing(filing_type: str, filing_data: bytes,
                            forged_privkey: bytes) -> bytes:
    """Forge a signed regulatory filing (EDGAR, bank regulator report).

    z/OS COBOL programs sign regulatory filings with CSNDRSA before
    submission. A forged signature makes fraudulent filings appear
    to originate from the bank's z/OS system.
    """
    f = PolynomialFactorer()
    return f.forge_pkcs1v15_signature(ZOS_ATTLS_PUBKEY_PEM, filing_data, "sha256")


if __name__ == "__main__":
    print("[1] Extracting z/OS AT-TLS RSA-2048 cert from TLS handshake")
    pubkey = extract_zos_pubkey(b"<tls-capture>")

    print("[2] Factoring ICSF RSA-2048 key")
    forged_priv = factor_zos_key(pubkey)
    print("    z/OS ICSF key recovered — CEX hardware bypassed")

    print("[3] Forging SWIFT MT103 payment instruction")
    payment = forge_swift_payment(
        "DEUTDEFF", "BNPAFRPP", 49_999_999.00, "REF-2026-ATTACK"
    , forged_priv)
    print(f"    MT103: {payment['mt103'][:40]}...")
    print(f"    CSNDRSA signature: {payment['signature']}")

    print("[4] Unwrapping master key hierarchy via CSNDPKE")
    master_key = unwrap_master_key(b"<wrapped-aes-master>", forged_priv)
    print("    AES master key exposed — entire key hierarchy compromised")
    print("    Every DES/AES session key in every CICS region decryptable")

    print("\n[5] Scale: 30 billion z/OS transactions/day globally")
    print("    COBOL programs calling CSNDRSA are not getting rewritten soon")
    print("    z/OS non-RSA migration: slowest in this repo")
