"""
ipaws_cap_sign.py

FEMA IPAWS CAP (Common Alerting Protocol) XML signing.
Sources:
  - OASIS Common Alerting Protocol v1.2 (July 2010)
  - IPAWS Profile v1.0 (FEMA, 2009; erratum through 2022)
  - FCC Part 11 (Emergency Alert System rules)
  - 47 CFR 10 (Commercial Mobile Alert Service / WEA)
  - FEMA "CAP Profile v1.0 for IPAWS" official specification

IPAWS alerting authorities obtain an RSA-2048 certificate after FEMA
approval (the IPAWS PIN program). They sign every CAP alert XML using
XMLDSig Enveloped signature with:
  - C14N: http://www.w3.org/2001/10/xml-exc-c14n#
  - Signature: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
  - Digest:    http://www.w3.org/2001/04/xmlenc#sha256

The IPAWS Master Endpoint (MEP) verifies the signature, applies routing
rules (by event code, geography, audience), and forwards the alert to:
  - CMSP (Commercial Mobile Service Provider) gateway for WEA push
  - EAS Participant feed for TV/radio broadcast interrupt
  - NOAA Weather Radio HazCollect tower broadcast
  - IPAWS-OPEN public feed

A forged RSA signature on a CAP alert bypasses all of this. The MEP
accepts it, and within seconds it reaches every phone in the target
polygon, every TV/radio station in the target area, every NOAA
weather radio receiver.
"""

import datetime
import uuid
from lxml import etree
from signxml import XMLSigner, XMLVerifier, methods
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography import x509


CAP_NS = "urn:oasis:names:tc:emergency:cap:1.2"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"


def build_wea_alert(sender: str, event_code: str, area_polygon: str,
                     headline: str, description: str,
                     urgency: str = "Immediate",
                     severity: str = "Extreme",
                     certainty: str = "Observed") -> etree._Element:
    """
    Construct a CAP v1.2 alert for WEA distribution.

    WEA requires specific CAP parameters including:
      - CMAMtext (<=90 chars, the text that appears on the phone)
      - CMAMlongtext (up to 360 chars, available on WEA 3.0 devices)
      - CMAMgeocode (CAP <geocode> for SAME FIPS codes)
      - CMACcategory (aligned with CAP <category>)

    event_code values: EVI (evacuation), SVR (severe weather),
    TOR (tornado), HMA (hazmat), EAN (Emergency Action Notification).
    """
    alert = etree.Element(f"{{{CAP_NS}}}alert")
    etree.SubElement(alert, f"{{{CAP_NS}}}identifier").text = str(uuid.uuid4())
    etree.SubElement(alert, f"{{{CAP_NS}}}sender").text = sender
    etree.SubElement(alert, f"{{{CAP_NS}}}sent").text = \
        datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S-00:00")
    etree.SubElement(alert, f"{{{CAP_NS}}}status").text = "Actual"
    etree.SubElement(alert, f"{{{CAP_NS}}}msgType").text = "Alert"
    etree.SubElement(alert, f"{{{CAP_NS}}}scope").text = "Public"

    info = etree.SubElement(alert, f"{{{CAP_NS}}}info")
    etree.SubElement(info, f"{{{CAP_NS}}}category").text = "Safety"
    etree.SubElement(info, f"{{{CAP_NS}}}event").text = event_code
    etree.SubElement(info, f"{{{CAP_NS}}}urgency").text = urgency
    etree.SubElement(info, f"{{{CAP_NS}}}severity").text = severity
    etree.SubElement(info, f"{{{CAP_NS}}}certainty").text = certainty
    etree.SubElement(info, f"{{{CAP_NS}}}headline").text = headline
    etree.SubElement(info, f"{{{CAP_NS}}}description").text = description

    # WEA CMAM parameters
    for name, value in [
        ("CMAMtext", headline[:90]),
        ("CMAMlongtext", description[:360]),
        ("CMAMcategory", "CEM"),  # Civil Emergency Message
        ("CMAMresponsetype", "Shelter"),
    ]:
        param = etree.SubElement(info, f"{{{CAP_NS}}}parameter")
        etree.SubElement(param, f"{{{CAP_NS}}}valueName").text = name
        etree.SubElement(param, f"{{{CAP_NS}}}value").text = value

    area = etree.SubElement(info, f"{{{CAP_NS}}}area")
    etree.SubElement(area, f"{{{CAP_NS}}}areaDesc").text = "Target area"
    etree.SubElement(area, f"{{{CAP_NS}}}polygon").text = area_polygon

    return alert


def sign_cap_alert(alert_elem: etree._Element,
                    rsa_private_key: rsa.RSAPrivateKey,
                    authority_cert: x509.Certificate) -> bytes:
    """
    XMLDSig-Enveloped signature over CAP alert using RSA-SHA256.
    Produces the signed XML that IPAWS MEP will accept and route.

    A classical factoring attack against the alerting authority's RSA-2048
    key (or against FEMA's IPAWS CA RSA key) lets an attacker produce
    outputs indistinguishable from this function, for any alert content
    they choose, under any authority identity.
    """
    signer = XMLSigner(
        method=methods.enveloped,
        signature_algorithm="rsa-sha256",
        digest_algorithm="sha256",
        c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
    )
    signed = signer.sign(
        alert_elem,
        key=rsa_private_key,
        cert=authority_cert.public_bytes(serialization.Encoding.PEM),
    )
    return etree.tostring(signed, xml_declaration=True, encoding="UTF-8")


def verify_cap_alert(signed_xml: bytes,
                      trust_anchor_certs: list) -> dict:
    """
    Verify a signed CAP alert against the IPAWS trust chain.
    Called by:
      - IPAWS Master Endpoint (before routing to WEA/EAS/NWR)
      - EAS encoders (Sage ENDEC, Digital Alert Systems DASDEC)
      - Cell carrier CMSP gateways
      - Any public consumer of IPAWS-OPEN (Google Public Alerts, etc.)
    """
    verifier = XMLVerifier()
    result = verifier.verify(signed_xml, x509_cert=trust_anchor_certs)
    # Extract CAP fields from verified signed data
    signed_elem = result.signed_xml
    return {
        "sender":     signed_elem.findtext(f".//{{{CAP_NS}}}sender"),
        "event":      signed_elem.findtext(f".//{{{CAP_NS}}}event"),
        "headline":   signed_elem.findtext(f".//{{{CAP_NS}}}headline"),
        "polygon":    signed_elem.findtext(f".//{{{CAP_NS}}}polygon"),
    }


def build_eas_same(event_code: str, location_fips: list[str],
                    duration_minutes: int,
                    originator: str = "CIV") -> str:
    """
    SAME (Specific Area Message Encoding) header for EAS activation.
    Built automatically by EAS encoders from the signed CAP alert —
    so a forged CAP alert produces a valid SAME header that every
    EAS-compliant broadcaster is FCC-mandated to carry.

    Format: ZCZC-{ORG}-{EEE}-{PSSCCC}[-{PSSCCC}...]+{TTTT}-{JJJHHMM}-{LLLLLLLL}-

    event_code: SAME event code — EVI (evacuation), TOR (tornado warning),
                SVR (severe thunderstorm), EAN (Emergency Action Notification,
                aka Presidential Alert).
    """
    now = datetime.datetime.utcnow()
    julian = now.strftime("%j%H%M")
    duration = f"{duration_minutes:04d}"
    locations = "-".join(location_fips)
    return f"ZCZC-{originator}-{event_code}-{locations}+{duration}-{julian}-IPAWS-"
