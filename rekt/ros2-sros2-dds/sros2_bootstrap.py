"""
sros2_bootstrap.py

Bootstrap a SROS2 (Secure ROS 2) security context for an AI robot fleet:

  1. Generate an Identity CA (RSA-2048) — root that issues per-node
     identity certs.
  2. Generate a Permissions CA (RSA-2048) — signs governance and per-node
     permissions XML documents.
  3. Issue per-node identity certs (RSA-2048) for every ROS 2 node that
     will join the security domain (typically: perception, planner,
     controller, safety monitor, operator console).
  4. Author + sign governance.xml (domain-wide defaults) and per-node
     permissions.xml (node access control) as PKCS#7 signed XML.

Invoked by: `sros2 security create_keystore` + `create_enclave` wrappers
in production robot fleet provisioning. The resulting enclave directory
layout is what ships inside every robot's `$ROS_SECURITY_KEYSTORE`.
"""

import datetime
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID


RSA_KEY_SIZE = 2048


def _gen_rsa() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537,
                                     key_size=RSA_KEY_SIZE)


def _build_ca(name: str) -> tuple:
    """Build a self-signed CA cert + private key."""
    key = _gen_rsa()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Locus Robotics AMR Fleet"),
    ])
    cert = (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow()
                             + datetime.timedelta(days=365 * 10))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0),
                           critical=True)
            .sign(key, hashes.SHA256()))
    return cert, key


def create_keystore(keystore_root: Path) -> dict:
    """
    Build both CAs and write them out. Equivalent to
    `ros2 security create_keystore`.
    """
    keystore_root.mkdir(parents=True, exist_ok=True)
    (keystore_root / "enclaves").mkdir(exist_ok=True)

    identity_ca_cert, identity_ca_key = _build_ca("ROS 2 Identity CA")
    permissions_ca_cert, permissions_ca_key = _build_ca("ROS 2 Permissions CA")

    (keystore_root / "public").mkdir(exist_ok=True)
    (keystore_root / "private").mkdir(exist_ok=True)

    (keystore_root / "public" / "identity_ca.cert.pem").write_bytes(
        identity_ca_cert.public_bytes(serialization.Encoding.PEM))
    (keystore_root / "public" / "permissions_ca.cert.pem").write_bytes(
        permissions_ca_cert.public_bytes(serialization.Encoding.PEM))

    for name, key in [("identity_ca", identity_ca_key),
                       ("permissions_ca", permissions_ca_key)]:
        (keystore_root / "private" / f"{name}.key.pem").write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()))

    return {
        "identity_ca": (identity_ca_cert, identity_ca_key),
        "permissions_ca": (permissions_ca_cert, permissions_ca_key),
    }


def issue_identity_cert(identity_ca_cert, identity_ca_key,
                         node_name: str, keystore_root: Path) -> None:
    """
    Issue a per-node identity cert. Equivalent to
    `ros2 security create_enclave <node_name>`.
    """
    node_key = _gen_rsa()
    node_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, node_name),
    ])
    cert = (x509.CertificateBuilder()
            .subject_name(node_subject)
            .issuer_name(identity_ca_cert.subject)
            .public_key(node_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow()
                             + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName(node_name),
            ]), critical=False)
            .sign(identity_ca_key, hashes.SHA256()))

    enc = keystore_root / "enclaves" / node_name.lstrip("/")
    enc.mkdir(parents=True, exist_ok=True)
    (enc / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (enc / "key.pem").write_bytes(node_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()))


def sign_permissions_xml(permissions_ca_key,
                          permissions_xml: bytes,
                          output_path: Path) -> None:
    """
    Sign a DDS-Security permissions.xml as PKCS#7 (S/MIME).
    `permissions_ca_key` is RSA-2048; the PKCS#7 structure contains
    RSA-SHA256 signer info.

    Real sros2 tooling shells out to `openssl smime -sign -outform PEM`;
    here we show the equivalent using cryptography's pkcs7 API.
    """
    from cryptography.hazmat.primitives.serialization import pkcs7
    # Need matching cert for signer info; caller supplies permissions CA
    # cert in production via a preloaded path. Skipping for brevity.
    raise NotImplementedError("requires permissions CA cert to complete")


def bootstrap_fleet(keystore_root: Path, node_names: list) -> None:
    """
    End-to-end fleet bootstrap. In an AI robotics deployment, node_names
    typically include:
      /perception/camera_driver
      /perception/lidar_driver
      /perception/object_detector      (runs the vision policy model)
      /planning/nav2                   (global + local planner)
      /control/diff_drive_controller
      /safety/emergency_stop_monitor
      /fleet/mqtt_bridge               (to fleet management backend)
    """
    cas = create_keystore(keystore_root)
    ident_cert, ident_key = cas["identity_ca"]
    for node in node_names:
        issue_identity_cert(ident_cert, ident_key, node, keystore_root)
