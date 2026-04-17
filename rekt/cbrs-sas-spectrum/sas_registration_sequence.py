"""
sas_registration_sequence.py

End-to-end SAS (Spectrum Access System) registration + grant cycle that
an actual CBSD (Citizens Broadband Radio Service Device) runs to operate
on the US 3.5 GHz band under FCC Part 96 rules.

This is the protocol state machine that wraps the mTLS / RSA-cert layer
in `cbrs_sas_auth.py`. Deployed inside base stations from Ericsson,
Nokia, Samsung, Airspan, Baicells, Cambium, Ruckus — every CBRS radio
sold in the US since 2020.

SAS operators: Google SAS, Federated Wireless SAS, CommScope/Sony SAS,
Amdocs SAS, RED Technologies SAS. Every CBSD talks to one of these.
"""

import json
import time
from typing import Optional
import requests


class CBSD:
    """Minimal CBSD state machine."""

    STATE_UNREGISTERED  = "UNREGISTERED"
    STATE_REGISTERED    = "REGISTERED"
    STATE_AUTHORIZED    = "AUTHORIZED"
    STATE_GRANTED       = "GRANTED"

    def __init__(self, sas_base_url: str,
                  tls_session: requests.Session,
                  fcc_id: str, cbsd_serial: str,
                  lat: float, lon: float, height_m: float):
        self.sas = sas_base_url
        self.s = tls_session        # mTLS-enabled session (WInnForum RSA cert)
        self.fcc_id = fcc_id
        self.cbsd_serial = cbsd_serial
        self.state = self.STATE_UNREGISTERED
        self.cbsd_id: Optional[str] = None
        self.grant_id: Optional[str] = None
        self.location = {"latitude": lat, "longitude": lon, "height": height_m}

    def register(self, category: str = "B") -> None:
        """Category A = low-power ≤ 30 dBm EIRP, B = higher ≤ 47 dBm."""
        body = {
            "registrationRequest": [{
                "userId":        "OPERATOR-12345",
                "fccId":         self.fcc_id,
                "cbsdSerialNumber": self.cbsd_serial,
                "callSign":      self.cbsd_serial,
                "cbsdCategory":  category,
                "airInterface":  {"radioTechnology": "E_UTRA"},
                "installationParam": {
                    "latitude":  self.location["latitude"],
                    "longitude": self.location["longitude"],
                    "height":    self.location["height"],
                    "heightType":"AGL",
                    "indoorDeployment": False,
                    "antennaGain": 15,
                    "antennaBeamwidth": 360,
                    "eirpCapability": 47,
                },
            }]
        }
        r = self.s.post(f"{self.sas}/registration", json=body, timeout=30)
        r.raise_for_status()
        resp = r.json()["registrationResponse"][0]
        if resp["response"]["responseCode"] != 0:
            raise RuntimeError(f"registration failed: {resp['response']}")
        self.cbsd_id = resp["cbsdId"]
        self.state = self.STATE_REGISTERED

    def grant(self, low_freq_hz: int, high_freq_hz: int,
               max_eirp_dBmMHz: int) -> None:
        """Ask SAS to allocate a frequency chunk."""
        body = {
            "grantRequest": [{
                "cbsdId":       self.cbsd_id,
                "operationParam": {
                    "maxEirp": max_eirp_dBmMHz,
                    "operationFrequencyRange": {
                        "lowFrequency":  low_freq_hz,
                        "highFrequency": high_freq_hz,
                    },
                },
            }]
        }
        r = self.s.post(f"{self.sas}/grant", json=body, timeout=30)
        r.raise_for_status()
        resp = r.json()["grantResponse"][0]
        if resp["response"]["responseCode"] != 0:
            raise RuntimeError(f"grant failed: {resp['response']}")
        self.grant_id = resp["grantId"]
        self.state = self.STATE_GRANTED

    def heartbeat_loop(self, interval_s: int = 60) -> None:
        """
        Every grant is periodically re-authorized via heartbeat. A
        heartbeat rejection (e.g., because Navy radar was detected by
        the ESC sensors) forces the CBSD off-channel within 60 s.
        Every heartbeat is mTLS-authenticated by the CBSD's RSA-2048
        cert under the WInnForum CBRS PKI.
        """
        while True:
            body = {"heartbeatRequest": [{
                "cbsdId":      self.cbsd_id,
                "grantId":     self.grant_id,
                "operationState": "AUTHORIZED",
            }]}
            r = self.s.post(f"{self.sas}/heartbeat", json=body, timeout=30)
            resp = r.json()["heartbeatResponse"][0]
            code = resp["response"]["responseCode"]
            if code == 0:
                self.state = self.STATE_AUTHORIZED
                time.sleep(resp.get("heartbeatInterval", interval_s))
            elif code in (500, 501):     # TERMINATED_GRANT / SUSPENDED_GRANT
                self.state = self.STATE_REGISTERED
                self.grant_id = None
                return


# A typical fleet deployment (e.g., a rural carrier running 1,500 CBRS
# cells across the midwest) spins up one CBSD instance per cell with
# shared WInnForum-PKI RSA credentials scoped by FCC ID. Every call
# above travels over mTLS with those RSA creds. Break the PKI and:
#   - Competing operators can impersonate your CBSDs to SAS, flipping
#     your grants off
#   - Rogue CBSDs can register under valid identities anywhere in the
#     band, bypassing the incumbent-protection ESC sensor network
#   - The Navy radar protection mechanism (the whole point of the
#     band-sharing scheme) collapses
