"""
remote_id_and_laanc.py

FAA Part 89 Remote ID (ASTM F3411-22a authenticated option) +
LAANC authorization flow. Runs on enterprise drone platforms
(Skydio X10D, Matrice 350 RTK ground-station app) and on counter-
UAS verifier apps used by law enforcement and airport operators
(Dedrone, Fortem, Anduril Lattice for Mission Autonomy).
"""
from __future__ import annotations

import hashlib
import json
import struct
import time
from dataclasses import dataclass

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509 import load_pem_x509_certificate
import jwt as pyjwt


# ----- 1. Remote ID authenticated broadcast frame -----
# F3411-22a MessageType 0x2 "Authentication" carries a 17-byte
# header + up to 63 bytes of auth payload; multi-page spanning is
# allowed. RSA signatures are split across pages.

F3411_MSG_BASIC_ID   = 0x0
F3411_MSG_LOCATION   = 0x1
F3411_MSG_AUTH       = 0x2
F3411_MSG_SELF_ID    = 0x3
F3411_MSG_SYSTEM     = 0x4
F3411_MSG_OPERATOR   = 0x5

@dataclass
class RemoteIDFrame:
    operator_id: str          # e.g. "FAA-12345678-XYZ" (UA serial)
    latitude_deg: float
    longitude_deg: float
    altitude_m: float
    speed_m_s: float
    timestamp: int
    control_station_lat: float
    control_station_lon: float

    def canonical_bytes(self) -> bytes:
        """Stable byte representation over which we sign."""
        return struct.pack(
            ">32sddfffddi",
            self.operator_id.encode().ljust(32, b"\x00"),
            self.latitude_deg, self.longitude_deg,
            self.altitude_m, self.speed_m_s, 0.0,
            self.control_station_lat, self.control_station_lon,
            self.timestamp,
        )


def sign_remote_id(frame: RemoteIDFrame, privkey: rsa.RSAPrivateKey) -> bytes:
    """Produce the F3411 authenticated-message signature payload."""
    payload = frame.canonical_bytes()
    sig = privkey.sign(
        payload,
        padding.PKCS1v15(),          # RSA-2048 PKCS#1 v1.5
        hashes.SHA256(),
    )
    return sig                       # 256 bytes, paged across frames


def verify_remote_id(frame: RemoteIDFrame, signature: bytes,
                     operator_cert_pem: bytes,
                     faa_trust_anchor_pem: bytes) -> bool:
    """Counter-UAS verifier path — run on Dedrone, Anduril, airport
    operations center consoles observing live drone traffic."""
    cert = load_pem_x509_certificate(operator_cert_pem)

    # Chain-verify up to the FAA Remote ID trust anchor.
    anchor = load_pem_x509_certificate(faa_trust_anchor_pem)
    if cert.issuer != anchor.subject:
        return False
    anchor.public_key().verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )

    # Verify the frame signature.
    try:
        cert.public_key().verify(
            signature,
            frame.canonical_bytes(),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except Exception:
        return False
    return True


# ----- 2. LAANC authorization request + grant -----

LAANC_USS_URL = "https://laanc.uss-provider.com/api/v1"

def request_laanc_authorization(
    operator_cert_path: str,
    operator_key_path: str,
    mission: dict,
) -> dict:
    """Submit a LAANC request to an FAA-approved USS.

    Mission dict carries: operator_id, uas_serial, airspace (ICAO
    airport ID), altitude_ft_agl, start_time, end_time, bounding
    polygon.

    The USS authenticates us via TLS mutual-auth (operator's RSA
    cert), evaluates the request against the UAS Facility Map
    (UASFM) altitude ceiling for that airspace, and responds with
    a signed authorization token.
    """
    r = requests.post(
        f"{LAANC_USS_URL}/authorizations",
        json=mission,
        cert=(operator_cert_path, operator_key_path),
        verify="/etc/ssl/certs/ca-certificates.crt",
        timeout=10,
    )
    r.raise_for_status()
    return r.json()    # contains {"auth_token": "<JWT RS256>", ...}


def verify_laanc_grant(auth_token: str, uss_jwks_url: str) -> dict:
    """Enforcement / ramp-check scenario: inspector pulls token
    off the drone (QR code on the airframe or operator app), fetches
    the USS's JWKS, and verifies the RS256 signature + claims."""
    jwks = requests.get(uss_jwks_url, timeout=5).json()
    header = pyjwt.get_unverified_header(auth_token)
    key = next(k for k in jwks["keys"] if k["kid"] == header["kid"])

    claims = pyjwt.decode(
        auth_token,
        key=pyjwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key)),
        algorithms=["RS256"],
        audience="faa.gov/laanc",
    )
    assert claims["exp"] > int(time.time()), "grant expired"
    return claims


# ----- 3. Drone firmware update verify (client-side) -----

def drone_verify_firmware(image_bytes: bytes,
                          oem_sig_der: bytes,
                          oem_pubkey_pem: bytes) -> bool:
    pubkey = serialization.load_pem_public_key(oem_pubkey_pem)
    try:
        pubkey.verify(
            oem_sig_der,
            image_bytes,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except Exception:
        return False
    return True


# ----- Runtime glue on the drone -----
# - Flight-controller boot:   drone_verify_firmware()
# - Pre-flight:               request_laanc_authorization(); store grant
# - In-flight @ 1 Hz:         broadcast RemoteIDFrame + signature
# - Counter-UAS observer:     verify_remote_id()
# - FAA/law-enforcement ramp: verify_laanc_grant()

#
# ---- Breakage ----
#
# Factor the FAA Remote ID trust anchor:
#   - Attacker signs Remote ID broadcasts impersonating any operator
#     ID. Enforcement attributions misdirect to innocent parties.
#     A drone flown near an airport (KFK-class incident) is logged
#     as flown by "John Smith, FAA reg XYZ" — who was nowhere near.
#
# Factor a drone OEM firmware-signing key (DJI, Skydio):
#   - Push signed firmware disabling geo-fencing, Remote ID, or
#     altitude limits across the OEM's global fleet. Airspace-
#     safety events at the scale of tens of millions of consumer
#     drones.
#
# Factor a LAANC USS RS256 signing key:
#   - Mint LAANC authorizations for arbitrary airspace/time/altitude.
#     Grant-free flight into controlled airspace with FAA-
#     recognized authorization evidence that validates under
#     enforcement ramp check.
#
# Factor the InterUSS DSS key (U-space, EU):
#   - Inject forged flight-plan conflicts to ground legitimate
#     operators; or cover forged plans that contradict legitimate
#     reservations in the Discovery service.
