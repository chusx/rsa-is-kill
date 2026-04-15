"""
cap_ingest_and_wea_emit.py

IPAWS-adjacent ingester: verifies CAP 1.2 XMLDSig signatures on
incoming NWS / state-EM warnings, gates WEA + EAS + NOAA Weather
Radio emission on successful verification. Pattern aligns with
FEMA IPAWS OPEN + state-EOC bridges + broadcast EAS/CAP gateways
(Sage Digital ENDEC, Trilithic / Viavi).
"""
from __future__ import annotations
import hashlib
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509 import load_pem_x509_certificate
import lxml.etree as ET


CAP_NS = {"cap": "urn:oasis:names:tc:emergency:cap:1.2",
          "ds":  "http://www.w3.org/2000/09/xmldsig#"}


# ---------------------------------------------------------------
# 1. CAP signature verification
# ---------------------------------------------------------------

def verify_cap_xmldsig(xml_bytes: bytes,
                       ipaws_root: rsa.RSAPublicKey) -> dict:
    root = ET.fromstring(xml_bytes)
    sig_el = root.find("ds:Signature", CAP_NS)
    if sig_el is None:
        raise ValueError("unsigned CAP")

    # Certificate is inline in <ds:KeyInfo><ds:X509Data><ds:X509Certificate>
    cert_b64 = sig_el.findtext("ds:KeyInfo/ds:X509Data/ds:X509Certificate",
                               namespaces=CAP_NS)
    pem = b"-----BEGIN CERTIFICATE-----\n" \
          + cert_b64.strip().encode() \
          + b"\n-----END CERTIFICATE-----\n"
    cert = load_pem_x509_certificate(pem)

    # Chain up to IPAWS root — originator certs are intermediates
    ipaws_root.verify(
        cert.signature, cert.tbs_certificate_bytes,
        padding.PKCS1v15(), cert.signature_hash_algorithm,
    )

    # C14N-exclusive over the <SignedInfo>; digest over canonicalised
    # enveloped <alert> minus <Signature>. (XMLDSig is notoriously
    # easy to misimplement — production code uses a library.)
    signed_info = sig_el.find("ds:SignedInfo", CAP_NS)
    si_bytes = ET.tostring(signed_info, method="c14n",
                           exclusive=True, with_comments=False)
    sig_b64 = sig_el.findtext("ds:SignatureValue", namespaces=CAP_NS)
    sig = _b64(sig_b64)

    cert.public_key().verify(
        sig, si_bytes, padding.PKCS1v15(), hashes.SHA256(),
    )

    # Still must verify the <ds:Reference> digest vs canonicalised
    # <alert>-minus-<Signature> — elided here.

    return _parse_cap_alert(root)


# ---------------------------------------------------------------
# 2. Alert domain model + WEA eligibility
# ---------------------------------------------------------------

@dataclass
class Alert:
    sender: str                  # e.g. "w-nws.webmaster@noaa.gov"
    identifier: str
    sent_ts: str
    msg_type: str                # Alert | Update | Cancel
    scope: str                   # Public | Restricted | Private
    status: str                  # Actual | Exercise | Test | Draft
    event: str                   # "Tsunami Warning", "Tornado Warning"
    severity: str                # Extreme | Severe | Moderate | Minor
    urgency: str                 # Immediate | Expected | Future
    certainty: str               # Observed | Likely | Possible
    areas: list[str]             # UGC zones / SAME codes
    headline: str
    body: str


WEA_ELIGIBLE_EVENTS = {
    "Tornado Warning", "Flash Flood Warning",
    "Tsunami Warning", "Hurricane Warning", "Extreme Wind Warning",
    "Dust Storm Warning", "Storm Surge Warning",
    "Blue Alert", "AMBER Alert",
    "Presidential Alert",
    "Public Safety Alert",
}


def is_wea_eligible(a: Alert) -> bool:
    if a.status != "Actual":   return False
    if a.scope != "Public":    return False
    if a.msg_type == "Cancel": return False
    return (a.event in WEA_ELIGIBLE_EVENTS
            and a.severity in ("Extreme", "Severe")
            and a.urgency == "Immediate"
            and a.certainty in ("Observed", "Likely"))


# ---------------------------------------------------------------
# 3. WEA / EAS emission — only after signature gate
# ---------------------------------------------------------------

def ipaws_gate_and_emit(xml_bytes: bytes,
                        ipaws_root: rsa.RSAPublicKey) -> Optional[str]:
    alert = verify_cap_xmldsig(xml_bytes, ipaws_root)

    if alert.status in ("Test", "Exercise"):
        emit_test_channel(alert)
        return "test"

    if is_wea_eligible(alert):
        # Cell carriers ingest via IPAWS OPEN; broadcasters via
        # Sage ENDEC; NWR via NOAA Weather Radio tone.
        wea_broadcast(alert)
        eas_broadcast(alert)
        nwr_broadcast(alert)
        return "emitted"

    return "filed"


# ---------------------------------------------------------------
# 4. NEXRAD product signature check (stream of products)
# ---------------------------------------------------------------

def verify_nexrad_product(hdr_sig: bytes, body: bytes,
                          nws_product_pub: rsa.RSAPublicKey) -> None:
    h = hashlib.sha256(body).digest()
    nws_product_pub.verify(
        hdr_sig, h, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=32),
        hashes.Prehashed(hashes.SHA256()),
    )


# ---------------------------------------------------------------

def _b64(s: str) -> bytes:
    import base64
    return base64.b64decode("".join(s.split()))


def _parse_cap_alert(root) -> Alert:
    ...


def emit_test_channel(a: Alert) -> None: ...
def wea_broadcast(a: Alert) -> None: ...
def eas_broadcast(a: Alert) -> None: ...
def nwr_broadcast(a: Alert) -> None: ...


# ---- Breakage ------------------------------------------------------
#
#   FEMA IPAWS root factored:
#     - Forged WEA / EAS messages indistinguishable from real.
#       2018 Hawaii false-alarm scaled by cryptographic
#       authority — nationwide panic + economic disruption.
#
#   NWS CAP signing cert factored:
#     - Fake tsunami / tornado warnings at media scale.
#       Alternatively, denial of real warnings by flooding
#       IPAWS with verification-failing look-alikes.
#
#   NEXRAD product signing key factored:
#     - Radar products downstream into aviation / media stream
#       no longer trustworthy; TV stations choose between
#       stale data and unverified real-time.
#
#   Tsunami / VAAC signing root factored:
#     - Coastal evacuation + aviation rerouting chains break.
#       Wrong decisions made at multi-minute cadence.
