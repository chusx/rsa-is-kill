"""
alert_originator_workflow.py

FEMA IPAWS (Integrated Public Alert and Warning System) OpenPlatform
for Emergency Networks (OPEN) — alert originator side. This is the
operator console flow at a state EOC, National Weather Service
forecast office, or local Emergency Management Agency that publishes
CAP 1.2 alert messages that ultimately ring every WEA-capable cell
phone in the affected polygon and every NOAA Weather Radio + EAS
broadcast participant (radio, TV, cable).

The XMLDSig RSA signing primitives are in `ipaws_cap_sign.py`; this
file is the orchestration around them, including the cross-check
against the IPAWS-OPEN aggregator's COG/CAP schema rules before a
message goes live.

Authorized IPAWS Alert Originators (AOs): ~1,600 entities —
  - State & Territorial Emergency Management Agencies (CA OES,
    Texas DEM, NYC OEM, FL DEM, Puerto Rico PREMA, etc.)
  - NWS Weather Forecast Offices (x122 in the U.S.)
  - County / tribal EMAs
  - USGS (earthquake ShakeAlert), USCG (local notices to mariners)
  - Military installations (base lockdown AMBER/Blue alerts)
"""

import datetime
import uuid
from ipaws_cap_sign import sign_cap_xmldsig, verify_cap_xmldsig


CAP_NS = "urn:oasis:names:tc:emergency:cap:1.2"
IPAWS_NS = "http://www.fema.gov/IPAWS-OPEN/Version4"


class IpawsAlertOriginator:
    def __init__(self, cog_id: str, signing_key_p12: bytes,
                  signing_key_pass: str):
        self.cog_id = cog_id            # Collaborative Operating Group ID
        self._key   = signing_key_p12   # P12 w/ RSA-2048 private + IPAWS-issued leaf
        self._pw    = signing_key_pass

    # ---- Compose + sign + post ----

    def issue_wea(self, *, event: str, severity: str,
                   headline: str, description: str,
                   polygon_wkt: str, expires_minutes: int,
                   handling: str = "Actual"):
        """
        Wireless Emergency Alert.  Six classes are wired into WEA
        presentation on the phone (AMBER, Imminent Threat - Extreme,
        Public Safety, Presidential, Test, Opt-in Missing).
        """
        now = datetime.datetime.utcnow().replace(microsecond=0)
        msg = {
            "identifier": f"{self.cog_id}-{uuid.uuid4()}",
            "sender":     self.cog_id,
            "sent":       now.isoformat() + "Z",
            "status":     handling,
            "msgType":    "Alert",
            "scope":      "Public",
            "restriction": None,
            "code":       ["IPAWSv1.0"],
            "info": [{
                "category":   "Safety",
                "event":      event,
                "urgency":    "Immediate",
                "severity":   severity,
                "certainty":  "Observed",
                "effective":  now.isoformat() + "Z",
                "expires":   (now + datetime.timedelta(minutes=expires_minutes)).isoformat() + "Z",
                "senderName": self.cog_id,
                "headline":   headline,   # ≤90 chars WEA limit
                "description": description,
                "area": [{"areaDesc": "WEA polygon",
                          "polygon":   polygon_wkt}],
                "parameter": [
                    {"valueName": "WEAHandling", "value": "Imminent Threat"},
                    {"valueName": "CMAMtext",    "value": headline[:90]},
                    {"valueName": "CMAMlongtext","value": description[:360]},
                    {"valueName": "EAS-ORG",     "value": "CIV"},
                ],
            }],
        }
        xml = self._render_cap_xml(msg)

        # XMLDSig enveloped RSA-SHA256 signature under the COG's
        # IPAWS-issued cert.  IPAWS-OPEN rejects messages whose
        # signature does not chain to the FEMA-operated IPAWS CA.
        signed_xml = sign_cap_xmldsig(xml, self._key, self._pw)

        # Local sanity check before wire submission.
        assert verify_cap_xmldsig(signed_xml), "self-sign/verify failed"

        self._post_to_ipaws_open(signed_xml)

    # ---- Pre-flight validators (schema + content) ----

    def _render_cap_xml(self, msg: dict) -> bytes: ...
    def _post_to_ipaws_open(self, signed_xml: bytes) -> None:
        # SOAP POST over TLS to https://tdl.qa.fema.gov/IPAWS_CAPService/
        # (prod: https://apps.fema.gov/IPAWS_CAPService/).  Client-cert
        # auth required, separate from the XMLDSig key.
        ...


# ---- Breakage ----
#
# The IPAWS CA signs every AO's XMLDSig signing cert.  A factoring
# attack on the IPAWS CA (RSA-2048, operated by FEMA) lets an attacker
# mint AO certs for any COG in the country and push CAP alerts that
# IPAWS-OPEN accepts as authoritative — fanned out to:
#   - Every WEA-capable phone in a polygon (nationwide Presidential
#     Alert is one message away)
#   - Every EAS Participant (Primary Entry Point radio, state
#     relays, cable headends, broadcast TV master controls)
#   - NWR transmitters
# The capability to trigger an unattributed "missile inbound" alert
# nationwide is a textbook asymmetric-warfare primitive; see the 2018
# Hawaii false-alarm incident (human error, not crypto) for the public
# reaction calibration.
