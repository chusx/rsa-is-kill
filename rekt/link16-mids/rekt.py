"""
Factor the NATO KMF provisioning RSA key to mint forged SKL credentials,
exfiltrate Link 16 COMSEC waveform keys, and forge signed mission-plan loads —
enabling real-time SIGINT on NATO tactical data links and blue-on-blue risk
via altered engagement assignments.
"""

import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import struct
import hashlib
import os

# KMF (Key Management Facility) RSA key — used for SKL authentication
KMF_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."
# MIDS ECU firmware signing key
MIDS_FW_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."
# Mission-plan signing key (service PKI)
MISSION_SIGN_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."


def extract_kmf_pubkey(skl_firmware: bytes) -> bytes:
    """Extract KMF provisioning RSA key from SKL (Simple Key Loader) firmware.

    SKL (AN/PYQ-10, NGLD-M) authenticates to the KMF via RSA.
    The KMF cert is in the SKL firmware or in the fill-device trust store.
    """
    return KMF_PUBKEY_PEM


def factor_kmf_key(pubkey_pem: bytes) -> bytes:
    """Factor the NATO KMF provisioning RSA key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def forge_skl_credential(terminal_sn: str, forged_privkey: bytes) -> bytes:
    """Forge a SKL credential that authenticates to the KMF.

    With a forged SKL credential, request fills of COMSEC keys
    for any Link 16 network (MIDS terminal crypto-period keys).
    """
    cred = struct.pack(">16sI", terminal_sn.encode()[:16], int(os.urandom(4).hex(), 16))
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(KMF_PUBKEY_PEM, cred, "sha256")
    return cred + sig


def exfiltrate_comsec_keys(forged_skl_cred: bytes) -> dict:
    """Use forged SKL credential to request COMSEC key fills.

    COMSEC keys are the symmetric keys that protect the actual
    Link 16 waveform. With these, real-time SIGINT on NATO
    tactical data link is possible.
    """
    return {
        "keys_obtained": ["TSEC/KGV-11 fill set A", "TSEC/KGV-11 fill set B"],
        "network": "Link 16 MIDS-LVT",
        "crypto_period": "current + next",
        "sigint_capability": "real-time track/engagement data visible",
    }


def forge_mission_load(aircraft: str, iff_codes: dict,
                       no_strike_coords: list, forged_privkey: bytes) -> bytes:
    """Forge a signed mission data file (DTC/PMDS/PMDL) for an aircraft.

    Mission loads contain ROE-relevant data: IFF responder codes,
    no-strike coordinates, jammer profiles. Altering these creates
    blue-on-blue risk during active operations.
    """
    mission = struct.pack(">16s", aircraft.encode()[:16])
    for code_type, code_val in iff_codes.items():
        mission += struct.pack(">8sI", code_type.encode()[:8], code_val)
    for lat, lon in no_strike_coords:
        mission += struct.pack(">ff", lat, lon)
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(MISSION_SIGN_PUBKEY_PEM, mission, "sha256")
    return mission + sig


if __name__ == "__main__":
    print("[1] Extracting KMF provisioning RSA key from SKL firmware")
    pubkey = extract_kmf_pubkey(b"<skl-firmware>")

    print("[2] Factoring NATO KMF RSA key")
    forged_priv = factor_kmf_key(pubkey)
    print("    KMF provisioning key recovered")

    print("[3] Forging SKL credential")
    skl_cred = forge_skl_credential("MIDS-JTRS-0042", forged_priv)
    print(f"    SKL credential: {len(skl_cred)} bytes, KMF-authenticated")

    print("[4] Exfiltrating COMSEC keys via forged SKL")
    keys = exfiltrate_comsec_keys(skl_cred)
    print(f"    {keys}")
    print("    Real-time SIGINT on NATO Link 16 — force composition,")
    print("    engagement assignments, IFF state visible to adversary")

    print("\n[5] Forging mission load — altered no-strike coordinates")
    mission = forge_mission_load(
        "F-16C Block 52",
        {"Mode4A": 0x1234, "Mode4B": 0x5678},
        [(33.5, 36.3), (33.6, 36.4)],  # altered coords
        forged_priv
    )
    print(f"    Mission load: {len(mission)} bytes, service PKI signed")
    print("    Blue-on-blue risk from altered ROE inputs")

    print("\n[*] Platform lifecycle: 30-40 years")
    print("    Cryptographic rotation touches every NATO airframe")
