"""
Factor a Cisco IOS-XE router's RSA-2048 SSH host key from a network scan,
perform SSH MitM between the admin and the router, and capture credentials
for the entire enterprise management plane.
"""

import sys, hashlib
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

# Cisco IOS key types — no ML-DSA equivalent
IOS_KEY_TYPES = ["rsa"]  # crypto key generate ? -> rsa, ec (only)
SCEP_OID_RSA = "1.2.840.113549.1.1.1"  # rsaEncryption


def extract_ssh_host_key(router_ip: str, port: int = 22) -> bytes:
    """Extract the RSA-2048 SSH host key from a Cisco IOS-XE device.
    Sent in cleartext during SSH key exchange."""
    print(f"    SSH connect to {router_ip}:{port}")
    print("    extracting server host key from SSH_MSG_KEXINIT")
    print("    ssh-rsa key, 2048 bits")
    return b"-----BEGIN RSA PUBLIC KEY-----\nMIIB...\n-----END RSA PUBLIC KEY-----\n"


def extract_tls_cert(router_ip: str, port: int = 443) -> bytes:
    """Extract the RSA-2048 cert from the HTTPS management interface."""
    print(f"    TLS connect to {router_ip}:{port}")
    print("    RSA-2048 cert from ServerHello")
    return b"-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----\n"


def factor_router_key(pubkey_pem: bytes) -> bytes:
    factorer = PolynomialFactorer()
    return factorer.reconstruct_privkey(pubkey_pem)


def ssh_mitm(router_ip: str, admin_ip: str, forged_hostkey: bytes):
    """Position as SSH MitM between admin and router.
    Host fingerprint matches because we have the real private key."""
    print(f"    intercepting SSH from {admin_ip} to {router_ip}")
    print("    presenting forged host key — fingerprint matches admin's known_hosts")
    print("    admin authenticates with password (captured)")
    print("    relaying commands to real router — transparent proxy")


def impersonate_to_nms(router_ip: str, nms_ip: str, forged_cert: bytes):
    """Impersonate the router to Cisco DNA Center / Prime / SolarWinds."""
    print(f"    impersonating {router_ip} to NMS at {nms_ip}")
    print("    RESTCONF/NETCONF over HTTPS with forged cert")
    print("    NMS pushes config changes — we ACK and do nothing")
    print("    or: intercept config, modify, relay to real router")


def forge_ikev2_identity(router_cert: bytes, peer_ip: str):
    """Forge IKEv2 certificate-based authentication."""
    print(f"    IKEv2 AUTH to {peer_ip}")
    print("    forged device cert in IKE_AUTH")
    print("    site-to-site VPN established with attacker as legitimate site")


if __name__ == "__main__":
    print("[*] Cisco IOS-XE RSA key management plane attack")
    router = "10.0.0.1"

    print(f"[1] extracting SSH host key from {router}")
    ssh_key = extract_ssh_host_key(router)
    print("    crypto key generate rsa modulus 2048 (IOS-XE default)")

    print(f"[2] extracting HTTPS cert from {router}:443")
    tls_cert = extract_tls_cert(router)
    print("    same RSA-2048 key used for SSH, HTTPS, IKEv2")

    print("[3] factoring router RSA-2048 key")
    factorer = PolynomialFactorer()
    print("    p, q recovered — router identity key derived")

    print("[4] SSH MitM: capturing admin credentials")
    ssh_mitm(router, "10.0.0.100", b"FORGED_KEY")

    print("[5] impersonating router to Cisco DNA Center")
    impersonate_to_nms(router, "10.0.0.50", b"FORGED_CERT")

    print("[6] IKEv2 VPN: joining SD-WAN fabric as legitimate site")
    forge_ikev2_identity(b"FORGED_CERT", "10.0.1.1")

    print("[7] enterprise-wide impact:")
    print("    - Cisco DNA Center manages thousands of devices via SCEP+RSA")
    print("    - every ISR, Catalyst, ASR with RSA-2048 identity cert compromised")
    print("    - DoD networks: CAC/PIV device authentication uses RSA-2048")
    print("    - IOS-XE crypto key generate ? -> rsa, ec only (no ML-DSA)")
    print("[*] network-wide IOS-XE update for non-RSA: multi-year enterprise project")
