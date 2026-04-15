"""
direct_smime_and_fhir_udap.py

Two healthcare interop paths through the same RSA primitive:

  1. DIRECT Project secure clinical messaging: build + send a CCDA
     over S/MIME + SMTP to another provider's DIRECT address.

  2. SMART-on-FHIR Backend Services authentication: produce a
     signed RS256 JWT client assertion and exchange for an access
     token at an EHR's OAuth 2.0 token endpoint, then query the
     FHIR API.

This is roughly what runs inside every EHR (Epic Care Everywhere,
Cerner Millennium Direct, Meditech HISP, athenahealth Direct) and
every FHIR-talking third-party app (health-plan member apps,
pharmacy portals, specialist-referral systems, UDAP clients).
"""
from __future__ import annotations

import base64
import email
import hashlib
import smtplib
import time
import uuid
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart

import jwt as pyjwt
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12


# ============================================================
# 1. DIRECT Project — clinical message send
# ============================================================

def build_and_sign_ccda_for_direct(
    ccda_xml: bytes,
    sender_address: str,          # "jane.doe@direct.hospital.org"
    recipient_address: str,
    sender_p12_path: str,
    recipient_cert_pem: bytes,
) -> bytes:
    """Build a DIRECT-compliant S/MIME message:
       multipart/signed(RSA) enveloping a multipart/mixed that carries
       the CCDA, then encrypted (RSA-OAEP content-encryption-key wrap)
       to the recipient cert."""
    from cryptography.hazmat.primitives.serialization import pkcs7
    from cryptography.hazmat.primitives.serialization.pkcs7 import (
        PKCS7SignatureBuilder, PKCS7Options,
    )

    # --- inner MIME: CCDA attachment --------------------------------
    inner = MIMEMultipart("mixed")
    inner["From"] = sender_address
    inner["To"] = recipient_address
    inner["Subject"] = "Referral - CCDA"
    att = MIMEApplication(ccda_xml, _subtype="xml")
    att.add_header("Content-Disposition", "attachment", filename="ccda.xml")
    inner.attach(att)
    inner_bytes = inner.as_bytes()

    # --- sign with sender's RSA key ---------------------------------
    with open(sender_p12_path, "rb") as f:
        priv, cert, chain = pkcs12.load_key_and_certificates(f.read(), b"")
    signed = (
        PKCS7SignatureBuilder()
        .set_data(inner_bytes)
        .add_signer(cert, priv, hashes.SHA256())
        .sign(serialization.Encoding.SMIME,
              [PKCS7Options.Binary])
    )

    # --- encrypt to recipient pubkey (content-encryption key wrap)
    #     In practice the cryptography lib emits CMS EnvelopedData via
    #     PKCS#7; depicted schematically here. --------------------
    # (Full CMS EnvelopedData construction omitted for brevity.)

    return signed


def send_direct_message(rsa_signed_smime: bytes,
                        hisp_relay: str,
                        sender: str,
                        recipient: str) -> None:
    """Push to sender's HISP (Health Information Service Provider)
    via authenticated SMTP submission. HISP then negotiates TLS and
    delivers to recipient HISP's MX."""
    msg = email.message_from_bytes(rsa_signed_smime)
    with smtplib.SMTP_SSL(hisp_relay, 465) as s:
        s.login(sender, os.environ["HISP_PASSWORD"])
        s.sendmail(sender, [recipient], msg.as_bytes())


# ============================================================
# 2. SMART-on-FHIR Backend Services / UDAP
# ============================================================

SMART_TOKEN_ENDPOINT = "https://fhir.ehr.example.org/oauth2/token"
FHIR_BASE = "https://fhir.ehr.example.org/api/FHIR/R4"


def build_smart_client_assertion(
    client_id: str,
    key_pem: bytes,
    kid: str,
) -> str:
    """Produce an RS256-signed JWT client assertion per SMART BSS
    section 2.2 + UDAP."""
    now = int(time.time())
    claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": SMART_TOKEN_ENDPOINT,
        "exp": now + 300,
        "jti": str(uuid.uuid4()),
    }
    headers = {"kid": kid, "alg": "RS256"}
    privkey = serialization.load_pem_private_key(key_pem, password=None)
    return pyjwt.encode(claims, privkey, algorithm="RS256", headers=headers)


def obtain_access_token(client_id: str, key_pem: bytes, kid: str,
                         scope: str) -> dict:
    assertion = build_smart_client_assertion(client_id, key_pem, kid)
    r = requests.post(
        SMART_TOKEN_ENDPOINT,
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": (
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
            "client_assertion": assertion,
            "scope": scope,
        },
        timeout=10,
    )
    r.raise_for_status()
    return r.json()


def query_patient_everything(token: str, patient_id: str) -> dict:
    """$everything returns the full patient FHIR graph — USCDI+."""
    r = requests.get(
        f"{FHIR_BASE}/Patient/{patient_id}/$everything",
        headers={"Authorization": f"Bearer {token}",
                 "Accept": "application/fhir+json"},
        timeout=60,
    )
    r.raise_for_status()
    return r.json()


# ============================================================
# 3. Inbound DIRECT — HISP-side RSA verify + decrypt
# ============================================================

def hisp_inbound_verify(smime_bytes: bytes,
                         dtrust_roots_pem: bytes) -> tuple[bool, bytes]:
    """Verify S/MIME RSA signature on inbound DIRECT message.
    Chain must reach a DirectTrust-accredited root. Return (ok,
    plaintext-inner)."""
    # Concept: parse PKCS#7 SignedData, walk signer cert chain up to
    # a DirectTrust anchor, RSA-verify signature over detached
    # content, decrypt the outer EnvelopedData with our HISP-held
    # private key.  Implementation omitted — just marks the verify
    # point.
    ok = True  # placeholder: real implementation as above
    inner = b""  # placeholder
    return ok, inner


# ---- Breakage ----
#
# A factoring attack against:
#
# - A DirectTrust-accredited CA: attacker mints a DIRECT cert
#   `malicious-clinician@direct.hospital.org`, sends a referral or
#   medication-order CCDA to any DIRECT recipient. Receiving EHR
#   verifies the signature and presents the message in the
#   clinician's inbox as authenticated. Malicious orders dispatched
#   under color of authority.
#
# - A SMART-on-FHIR client's registered JWKS key: attacker
#   authenticates as a legitimate app (e.g. a nationwide pharmacy-
#   benefit-manager's app) against every EHR where that client_id
#   is registered. Bulk-export of patient records across tens of
#   thousands of providers.
#
# - A TEFCA QHIN signing CA: cross-HIE impersonation scales across
#   the entire US health-data exchange fabric.
#
# Healthcare PKI rotation takes 1-3 years at scale; retention of
# historical signed clinical messages is 7-10 years under HIPAA/HITECH
# retention mandates. A factoring break produces a long ambiguity
# window for clinical-record attribution and HIPAA audit evidence.
