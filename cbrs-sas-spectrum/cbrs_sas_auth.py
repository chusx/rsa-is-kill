"""
cbrs_sas_auth.py

CBRS (Citizens Broadband Radio Service) — CBSD/SAS mutual TLS with RSA.
Sources:
  - WInnForum WINNF-TS-0016 (SAS-CBSD Interface Technical Specification)
  - WInnForum WINNF-TS-0022 (CBRS PKI Certificate Policy)
  - WInnForum WINNF-TS-0065 (SAS-SAS Interface Technical Specification)
  - FCC 47 CFR Part 96 (Citizens Broadband Radio Service)
  - FCC DA 18-1306 (SAS Certification Requirements)

CBRS PKI hierarchy:

    WInnForum CBRS Root CA  (RSA-2048, 20-yr)
              |
       +------+------+--------+----------+
       |             |        |          |
    SAS CA     CBSD CA    DP CA     Test Labs CA
       |             |        |
    SAS certs   CBSD certs  DP certs
    (issued to  (issued    (issued to
     FCC-certified  to OEMs   operators
     SAS operators:  like     front-ending
     Federated        Nokia,    multiple
     Wireless,       Ericsson, CBSDs)
     Google, etc.)   Airspan)

Every CBSD-to-SAS transaction uses mTLS:
  - Client cert: CBSD device certificate (chains to WInnForum Root via CBSD CA)
  - Server cert: SAS operator certificate (chains via SAS CA)
  - Key exchange: ECDHE (usually ECDHE-RSA-AES256-GCM-SHA384)
  - Client auth via the RSA-2048 cert (the TLS CertificateVerify)

Registration → Spectrum Inquiry → Grant → Heartbeat loop.
Without valid auth, CBSD cannot transmit legally in 3550-3700 MHz.
"""

import ssl
import json
import datetime
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID


def load_cbsd_credentials(cert_path: str, key_path: str, ca_bundle: str):
    """Load CBSD device cert and private key for mTLS session."""
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_bundle)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def cbsd_register(sas_url: str, fcc_id: str, cbsd_serial: str,
                   lat: float, lon: float, height_m: float,
                   height_type: str, antenna_gain_dbi: float,
                   mtls_context: ssl.SSLContext) -> dict:
    """
    Send cbsdRegistrationRequest to SAS.
    SAS response contains a cbsdId that is required for all subsequent
    Spectrum Inquiry, Grant, and Heartbeat calls.

    The RSA-2048 TLS client cert is what the SAS uses to bind this
    registration to a specific FCC-registered device.
    """
    payload = {
        "registrationRequest": [{
            "fccId": fcc_id,
            "cbsdCategory": "B",  # Category A (24 dBm EIRP) or B (47 dBm EIRP)
            "cbsdSerialNumber": cbsd_serial,
            "callSign": "",
            "userId": "enterprise-operator",
            "airInterface": {"radioTechnology": "E_UTRA"},
            "installationParam": {
                "latitude": lat,
                "longitude": lon,
                "height": height_m,
                "heightType": height_type,  # "AMSL" or "AGL"
                "indoorDeployment": False,
                "antennaGain": antenna_gain_dbi,
                "antennaAzimuth": 0,
                "antennaDowntilt": 0,
                "antennaBeamwidth": 360,
            },
            "measCapability": ["RECEIVED_POWER_WITHOUT_GRANT"],
        }]
    }
    response = requests.post(
        f"{sas_url}/v1.3/registration",
        json=payload,
        # Use the session's mTLS config:
        cert=(mtls_context.load_cert_chain, None),
        verify=True,
    )
    return response.json()


def cbsd_grant_request(sas_url: str, cbsd_id: str,
                        low_freq_hz: int, high_freq_hz: int,
                        max_eirp_dbm: float,
                        mtls_context: ssl.SSLContext) -> dict:
    """
    Request a spectrum grant for a specific frequency range at a specific
    max EIRP. SAS returns a grantId, channelType (PAL or GAA), and a
    heartbeatInterval. The CBSD must heartbeat within the interval or
    the grant terminates.
    """
    payload = {
        "grantRequest": [{
            "cbsdId": cbsd_id,
            "operationParam": {
                "maxEirp": max_eirp_dbm,
                "operationFrequencyRange": {
                    "lowFrequency": low_freq_hz,
                    "highFrequency": high_freq_hz,
                },
            },
        }]
    }
    response = requests.post(f"{sas_url}/v1.3/grant", json=payload)
    return response.json()


def verify_cbrs_cert_chain(cbsd_cert_pem: bytes,
                             trust_anchor_pem: bytes) -> bool:
    """
    Verify a CBSD device certificate chains to the WInnForum CBRS Root CA.
    Called by the SAS on every incoming TLS handshake.

    If the trust anchor RSA-2048 key is recoverable via factoring, any
    certificate chain can be forged — including SAS server certificates
    (breaking the SAS identity) or CBSD device certificates (allowing
    rogue device registration).
    """
    cbsd_cert = x509.load_pem_x509_certificate(cbsd_cert_pem)
    trust_anchor = x509.load_pem_x509_certificate(trust_anchor_pem)

    # Verify signature chain — simplified
    trust_anchor.public_key().verify(
        cbsd_cert.signature,
        cbsd_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cbsd_cert.signature_hash_algorithm,
    )
    return True


def issue_cbsd_cert(manufacturer_ca_key: rsa.RSAPrivateKey,
                     manufacturer_ca_cert: x509.Certificate,
                     cbsd_public_key: rsa.RSAPublicKey,
                     fcc_id: str, serial: str,
                     validity_years: int = 20) -> x509.Certificate:
    """
    CBSD CA signs a device certificate. Each OEM (Nokia, Ericsson, Airspan)
    runs one of these under the WInnForum CBSD CA umbrella.

    The output certificate is the mTLS client cert that a manufactured
    CBSD will present to any SAS. It's valid for ~20 years (device
    lifetime), so once issued, it sits in the device for the life of
    the deployment.

    This function is the forgeable step: factoring the WInnForum CBRS
    Root CA key or any CBSD CA key lets an attacker run this function
    with manufacturer_ca_key they shouldn't have.
    """
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CBRS CBSD"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"{fcc_id}:{serial}"),
    ])
    cert = (x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(manufacturer_ca_cert.subject)
        .public_key(cbsd_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(
            datetime.datetime.utcnow()
            + datetime.timedelta(days=365 * validity_years))
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True,
                content_commitment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ), critical=True)
        .sign(manufacturer_ca_key, hashes.SHA256())
    )
    return cert


# Regulatory context:
#
# The FCC licensed CBRS as a three-tier shared access framework specifically
# to enable shared use with incumbent Navy radar and federal users. The SAS
# dynamically assigns frequencies to avoid interfering with those incumbents.
#
# Every time a CBSD registers or requests a grant, the SAS makes an
# interference-avoidance decision using RSA-authenticated identities. If
# those identities can be forged:
#
#   - SAS cannot reliably identify who is transmitting where
#   - DPA (Dynamic Protection Area) activations against federal incumbents
#     cannot be trusted — rogue CBSDs can ignore grant suspensions
#   - PAL (Priority Access License) protection areas become enforceable
#     only on legitimate CBSDs, so forged GAA CBSDs can degrade PAL service
#
# The FCC coordinates CBRS with DoD (specifically Navy) via ESC (Environmental
# Sensing Capability) sensors that detect incumbent radar transmissions.
# ESC-triggered channel clearing orders propagate through SAS to CBSDs —
# but only reach the CBSDs the SAS knows about. Forged CBSD registrations
# create an invisible-to-SAS interference source that ESC cannot reach.
