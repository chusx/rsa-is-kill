"""
iso15118_tls_auth.py

ISO 15118-2:2014 "Road vehicles -- Vehicle to grid communication interface"
TLS mutual authentication between EV (EVCC) and charging station (SECC).

Standard: ISO 15118-2:2014, section 8.7 (TLS Security Profile)
GitHub reference: https://github.com/EcoG-io/iso15118 (SwitchEV/iso15118 fork)

Every public EV charging station running ISO 15118 requires:
- A TLS server certificate for the SECC (Supply Equipment Communication Controller)
- A contract certificate for the EV (signed by a Mobility Operator CA)
- A V2G Root CA certificate (issued by a Charging Ecosystem operator)

All of these are RSA-2048 or ECDSA P-256 per the ISO 15118-2 PKI profile.
ISO 15118-20 (2022) does not mandate PQC. V2G PKI has no PQC roadmap.

Key certificate hierarchy (ISO 15118-2 Annex D):
  V2GRootCA (RSA-2048 or ECDSA P-256)
    SubCA1 (RSA-2048)
      SubCA2 (RSA-2048)
        SECC Leaf Certificate (RSA-2048)     -- the charging station's TLS cert
        OEM Provisioning Certificate         -- burned into the EV at manufacture
        MO Sub-CA                            -- Mobility Operator CA
          Contract Certificate (RSA-2048)   -- the EV's "payment credential"
"""

import ssl
import socket
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.x509.oid import NameOID
import datetime

# ISO 15118-2 Table 3: RSA key sizes for V2G PKI
V2G_RSA_KEY_BITS = 2048  # required for all V2G PKI certificates

# ISO 15118-2 §8.7.3: TLS cipher suites (RSA key exchange)
ISO15118_TLS_CIPHERS = [
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",   # mandatory for SECC
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", # allowed
]

def generate_secc_certificate():
    """
    Generate an SECC (charging station) TLS certificate per ISO 15118-2.

    The SECC certificate is signed by the V2G SubCA2 certificate, which
    chains to the V2G Root CA. A CRQC factoring the SubCA2 RSA private
    key can issue arbitrary SECC certificates accepted by any EV.
    """
    # RSA-2048 private key for the charging station
    secc_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=V2G_RSA_KEY_BITS,   # ISO 15118-2 Table 3: RSA-2048
    )

    # Build the SECC certificate (per ISO 15118-2 Annex D.3)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SECC-CERT"),
    ])

    secc_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)  # would normally be signed by SubCA2
        .public_key(secc_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=730))
        # ISO 15118-2: SECC cert max validity 2 years
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=True, data_encipherment=False,
                key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(secc_key, hashes.SHA256())  # SHA256withRSA per ISO 15118-2
    )
    return secc_key, secc_cert


def generate_contract_certificate(ev_oem_prov_key):
    """
    Generate an EV Contract Certificate (the EV's "payment credential").

    The Contract Certificate is bound to the EV's OEM Provisioning Certificate,
    which is burned into the EV at manufacture and signed by the OEM CA.

    ISO 15118-2 §7.9.1: The EV's contract certificate contains an RSA-2048
    public key. The Mobility Operator issues it after EMAID (Electric Mobility
    Account Identifier) registration.

    Contract cert validity: up to 2 years (ISO 15118-2 Table 3).
    The OEM provisioning cert validity: up to 6 years.
    The car's lifespan: 10-15 years.
    """
    contract_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=V2G_RSA_KEY_BITS,
    )
    # contract_key stored in EV's secure element (TPM or HSM chip)
    # signs ISO 15118-2 PaymentDetailsReq messages during charging session
    return contract_key


def secc_tls_server(host, port, secc_cert_path, secc_key_path, v2g_root_ca_path):
    """
    SECC TLS server — the charging station's communication controller.

    Per ISO 15118-2 §8.7.3: mutual TLS is required. The SECC presents
    its SECC Leaf Certificate. The EV presents its Contract Certificate.

    TLS 1.2 is mandated by ISO 15118-2 (TLS 1.3 only in ISO 15118-20).
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.verify_mode = ssl.CERT_REQUIRED          # mutual TLS
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2  # ISO 15118-2 requires TLS 1.2

    # Load SECC RSA-2048 certificate and key
    context.load_cert_chain(secc_cert_path, secc_key_path)

    # Trust only the V2G Root CA (ISO 15118-2: one root per ecosystem)
    context.load_verify_locations(cafile=v2g_root_ca_path)

    # ISO 15118-2 mandatory cipher suite
    context.set_ciphers("ECDHE-RSA-AES128-SHA256")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, port))  # port 15118 is IANA-assigned for V2G
        sock.listen(1)
        with context.wrap_socket(sock, server_side=True) as ssock:
            conn, addr = ssock.accept()
            # ... handle ISO 15118-2 SupportedAppProtocol, SessionSetup, etc.


"""
CRQC attack on ISO 15118 charging infrastructure:

1. V2G Root CA RSA key compromise:
   - Forge SubCA1/SubCA2/SECC certificates for any charging station
   - Every EV in the ecosystem trusts the V2G Root CA
   - Impersonate any public charger, intercept EV payment credentials

2. MO Sub-CA RSA key compromise:
   - Forge Contract Certificates for any EV customer
   - Issue fake EMAID credentials tied to real customer accounts
   - Authorize free charging on any ISO 15118 network

3. OEM CA RSA key compromise:
   - Forge OEM Provisioning Certificates for any vehicle model
   - Impersonate any EV in the ecosystem (all vehicles of that manufacturer)

Scale: ISO 15118 is mandatory for CCS (Combined Charging System) in the EU
(EC Regulation 2023/1804). Every new public fast charger in Europe requires
ISO 15118 support. The automotive fleet lifespan is 10-15 years.
"""
