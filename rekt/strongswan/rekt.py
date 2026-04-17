"""
Forge RSA certificates for IKEv2 authentication to MitM IPsec site-to-site
VPN tunnels. strongSwan is the dominant open-source IKE daemon — site-to-site
between offices, data centers, cloud VPCs, and IEC 62443 OT networks.
"""
import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import hashlib
import os

# IKEv2 exchange types
IKE_SA_INIT = 34
IKE_AUTH = 35

# IKEv2 AUTH method
AUTH_RSA_DIGITAL_SIGNATURE = 1
AUTH_DIGITAL_SIGNATURE = 14  # RFC 7427 — still RSA in practice


def grab_ike_cert_from_handshake(gateway_ip: str, port: int = 500) -> bytes:
    """Grab the VPN gateway's RSA certificate from IKE_AUTH exchange.

    During IKE_AUTH, the responder sends its X.509 certificate in the
    CERT payload. Visible in any packet capture of the IKE exchange.
    """
    print(f"[*] initiating IKE_SA_INIT to {gateway_ip}:{port}")
    print("[*] IKE_AUTH: extracting CERT payload (RSA-2048 X.509)")
    return b"-----BEGIN CERTIFICATE-----\n...(VPN gateway cert)...\n-----END CERTIFICATE-----\n"


def forge_vpn_peer_cert(factorer: PolynomialFactorer,
                        ca_cert_pem: bytes,
                        peer_id: str) -> bytes:
    """Forge a VPN peer certificate for IKEv2 AUTH.

    strongSwan verifies the peer cert against the CA configured in
    ipsec.conf (leftca/rightca). Factor the CA and issue any peer cert.
    """
    priv = factorer.privkey_from_cert_pem(ca_cert_pem)
    print(f"[*] forged IKEv2 peer cert: ID={peer_id}")
    print("[*] issued_by() check in x509_cert.c: PASS")
    return priv


def forge_ike_auth_signature(factorer: PolynomialFactorer,
                             peer_cert_pem: bytes,
                             auth_data: bytes) -> bytes:
    """Forge the IKE_AUTH RSA signature.

    The AUTH payload contains an RSA signature over the IKE_SA_INIT
    message, nonce, and identity. This proves the peer holds the
    private key matching its certificate.
    """
    sig = factorer.forge_pkcs1v15_signature(peer_cert_pem, auth_data, "sha256")
    print("[*] forged IKE_AUTH RSA signature")
    print("[*] remote peer accepts our identity — tunnel established")
    return sig


def mitm_site_to_site(site_a: str, site_b: str):
    """MitM a site-to-site IPsec tunnel between two offices.

    We terminate the tunnel from both sides, decrypt, inspect,
    optionally modify, and re-encrypt. Both sides see valid certs.
    """
    print(f"[*] MitM tunnel: {site_a} <-> [attacker] <-> {site_b}")
    print("[*] both sides authenticate with forged certs -> PASS")
    print("[*] ESP traffic decrypted/re-encrypted transparently")
    print("[*] all inter-site traffic visible: AD replication, file shares,")
    print("    database traffic, VoIP, everything in the tunnel")


def attack_ot_ipsec(ot_gateway: str):
    """Attack IEC 62443 IPsec remote access to OT networks.

    Industrial control systems use strongSwan for secure remote access.
    Fork the IPsec peer auth -> inside the OT network.
    """
    print(f"[*] forging cert for OT remote access gateway: {ot_gateway}")
    print("[*] IEC 62443 secure remote access: cert auth is the only factor")
    print("[*] inside the OT network — SCADA, PLCs, safety systems")


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== strongSwan IKEv2 RSA certificate forgery ===")
    print("    dominant open-source IPsec on Linux, embedded, routers")
    print()

    print("[1] grabbing VPN gateway cert from IKE_AUTH exchange...")
    gw_cert = grab_ike_cert_from_handshake("vpn-gw.datacenter-b.example.com")

    print("[2] factoring VPN CA RSA-2048 key...")
    ca_cert = b"-----BEGIN CERTIFICATE-----\n...(VPN CA)...\n-----END CERTIFICATE-----\n"

    print("[3] forging peer certificate for site-to-site impersonation...")
    forge_vpn_peer_cert(f, ca_cert, "vpn-gw.datacenter-a.example.com")

    print("[4] forging IKE_AUTH signature...")
    auth_data = os.urandom(64)  # IKE_SA_INIT msg + nonce + ID
    forge_ike_auth_signature(f, ca_cert, auth_data)

    print("[5] MitM site-to-site tunnel...")
    mitm_site_to_site("datacenter-a", "datacenter-b")

    print("[6] attacking OT remote access...")
    attack_ot_ipsec("ot-vpn.chemical-plant.example.com")

    print()
    print("[*] RFC 8784 PPK: non-RSA key exchange but auth is still RSA certs")
    print("[*] 'post-quantum VPN' with only PPK is misleading")
