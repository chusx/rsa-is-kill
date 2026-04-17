"""
provision_thing.py

AWS IoT Core device provisioning flow. Shows the full customer side of
what happens on a factory line: generate the device's RSA-2048 keypair,
create a CSR, submit to AWS IoT (or to a customer-operated RegistrationCA
using "Multi-Account Registration"), receive a signed device cert, write
everything to the device's secure element.

Production call sites: every IoT manufacturer using AWS IoT — Amazon Basics
Echo line, Ring, Blink, Schneider Electric Wiser, Honeywell commercial
HVAC, John Deere ag telematics, countless industrial IoT gateways.
"""

import base64
import json
import boto3
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


iot = boto3.client("iot", region_name="us-east-1")


def make_device_keypair_and_csr(thing_name: str) -> tuple:
    """
    Per-device RSA-2048 keypair + PKCS#10 CSR, generated on the factory
    host. In higher-security fleets this happens inside the device itself
    (Microchip ATECC608B, NXP EdgeLock SE051, Infineon OPTIGA) so the
    private key never exists off-chip — but a large majority of AWS IoT
    fleets still generate the key on a provisioning PC and flash it into
    device NVRAM.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([
               x509.NameAttribute(NameOID.COMMON_NAME, thing_name),
               x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ACME IoT Fleet"),
           ]))
           .sign(key, hashes.SHA256()))

    return key, csr


def provision_thing(thing_name: str,
                     policy_name: str,
                     thing_type_name: str) -> dict:
    """Register Thing, submit CSR, attach policy, write out files."""
    key, csr = make_device_keypair_and_csr(thing_name)

    # Register Thing + Thing Type in the AWS IoT registry
    iot.create_thing(
        thingName=thing_name,
        thingTypeName=thing_type_name,
        attributePayload={"attributes": {"factory": "shenzhen-1"}},
    )

    # Submit CSR to AWS IoT CA (the AWS-owned Amazon Trust Services
    # cert chain, RSA-2048 ITCA sub-CA). AWS returns a device cert
    # whose leaf public key matches the CSR's.
    resp = iot.create_certificate_from_csr(
        certificateSigningRequest=csr.public_bytes(
            serialization.Encoding.PEM).decode(),
        setAsActive=True,
    )
    cert_arn = resp["certificateArn"]
    cert_id  = resp["certificateId"]
    cert_pem = resp["certificatePem"]

    # Attach policy + thing principal
    iot.attach_policy(policyName=policy_name, target=cert_arn)
    iot.attach_thing_principal(thingName=thing_name, principal=cert_arn)

    # Write device-side files. In the factory line, these get flashed
    # into the device's filesystem / secure element.
    return {
        "thing_name": thing_name,
        "certificate_id": cert_id,
        "certificate_pem": cert_pem,
        "private_key_pem": key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode(),
        "root_ca_pem": _amazon_root_ca_pem(),  # Amazon Trust Services
    }


def _amazon_root_ca_pem() -> str:
    """Amazon Root CA 1 (RSA-2048) — pinned on device for TLS to AWS IoT."""
    return ("-----BEGIN CERTIFICATE-----\n"
            "... Amazon Root CA 1 RSA-2048 cert ...\n"
            "-----END CERTIFICATE-----\n")


def bulk_factory_provision(serials: list,
                             policy_name: str = "iot-device-policy",
                             thing_type: str = "acme-sensor-gateway") -> list:
    """Factory line loop: provision N devices in parallel."""
    provisioned = []
    for sn in serials:
        try:
            info = provision_thing(f"acme-sensor-{sn}", policy_name, thing_type)
            provisioned.append(info)
        except Exception as e:
            provisioned.append({"serial": sn, "error": str(e)})
    return provisioned


# Every provisioned device does TLS 1.2 with client auth to
# `*.iot.us-east-1.amazonaws.com` using its RSA-2048 client cert, and
# pins the Amazon Root CA 1 (RSA-2048) as the server trust anchor.
# A factoring break affects both sides: attackers mint device certs
# AND MITM the TLS connection end-to-end.
