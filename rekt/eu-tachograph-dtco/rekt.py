"""
Factor the ERCA root or a VU manufacturer's signing key, forge workshop cards
that recalibrate tachographs at will, and enable fleet-wide driving-time fraud
across 6 million EU commercial vehicles with signed evidence that courts accept.
"""

import sys, struct, hashlib, time
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

# Smart Tachograph card types (EU 2021/1228)
CARD_DRIVER    = 0x01
CARD_WORKSHOP  = 0x02
CARD_COMPANY   = 0x03
CARD_CONTROL   = 0x04

# VU manufacturers
VU_VDO_DTCO_41 = "Continental VDO DTCO 4.1"
VU_STONERIDGE  = "Stoneridge SE5000 Exakt DUO+"


def extract_vu_manufacturer_key(vu_firmware: str) -> bytes:
    """Extract the VU manufacturer's firmware-signing RSA public key."""
    print(f"    VU firmware: {vu_firmware}")
    print(f"    manufacturer: {VU_VDO_DTCO_41}")
    return b"-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----\n"


def factor_vu_key(pubkey_pem: bytes) -> bytes:
    factorer = PolynomialFactorer()
    return factorer.reconstruct_privkey(pubkey_pem)


def mint_workshop_card(msca_privkey: bytes, workshop_name: str,
                       workshop_id: str) -> dict:
    """Mint a forged workshop card with calibration privileges."""
    return {
        "card_type": CARD_WORKSHOP,
        "workshop_name": workshop_name,
        "workshop_id": workshop_id,
        "valid_from": int(time.time()),
        "valid_until": int(time.time()) + 365 * 86400,
        "rsa_keypair_size": 2048,
    }


def calibrate_vu(workshop_card: dict, vu_serial: str,
                 new_odometer: int, new_tyre_circ_mm: int) -> dict:
    """Use the forged workshop card to recalibrate a Vehicle Unit.
    The calibration event is signed into the VU's event log."""
    return {
        "vu_serial": vu_serial,
        "calibration_date": int(time.time()),
        "odometer_km": new_odometer,
        "tyre_circumference_mm": new_tyre_circ_mm,
        "signed_by": workshop_card["workshop_id"],
        "signature": "RSA-2048/SHA-256 (forged workshop card)",
    }


def forge_ddd_download(driver_name: str, daily_records: list,
                       card_privkey: bytes) -> bytes:
    """Build a signed .ddd download file with forged activity records."""
    data = str({"driver": driver_name, "records": daily_records}).encode()
    sig = b"\x00" * 256
    return data + sig


if __name__ == "__main__":
    print("[*] EU Smart Tachograph (Gen2) signing attack")
    print("[1] extracting VU manufacturer firmware-signing key")
    pubkey = extract_vu_manufacturer_key("dtco_41_fw_v3.8.bin")

    print("[2] factoring VU manufacturer RSA-2048 key")
    factorer = PolynomialFactorer()
    print("    p, q recovered — Continental VDO signing key derived")

    print("[3] minting forged workshop card")
    ws_card = mint_workshop_card(b"MSCA_PRIVKEY", "Phantom Workshop GmbH", "WS-FAKE-001")
    print(f"    workshop: {ws_card['workshop_name']}")
    print("    calibration privileges for any VU")

    print("[4] recalibrating VU: odometer rollback")
    cal = calibrate_vu(ws_card, "DTCO41-SN-00142",
                       new_odometer=150000,  # rolled back from 450000
                       new_tyre_circ_mm=3200)
    print(f"    odometer: 450000 -> {cal['odometer_km']} km")
    print("    signed calibration event in VU log — forensically authoritative")

    print("[5] forging driver .ddd download: compliant hours")
    records = [{"date": f"2026-04-{d:02d}", "driving_h": 8.5, "rest_h": 11.5}
               for d in range(8, 15)]
    ddd = forge_ddd_download("Hans Schmidt", records, b"CARD_PRIVKEY")
    print("    7 days of compliant records (actual: 14h/day driving)")

    print("[6] DSRC roadside enforcement bypass")
    print("    Gen2 VU emits authenticated DSRC summary every 60s")
    print("    police roadside unit verifies signature before stopping vehicle")
    print("    forged summary shows compliant — truck not stopped")

    print("[7] impact:")
    print("    - ~6M Vehicle Units in EU + CH + UK fleets")
    print("    - ~12M active driver cards")
    print("    - ~25,000 authorised workshops")
    print("    - odometer fraud: second-hand truck market integrity")
    print("    - accident liability: overwrite post-crash driving records")
    print("    - Regulation 165/2014: any crypto change needs EU Commission amendment")
    print("[*] ERCA+MSCA is treaty-level cryptographic infrastructure")
