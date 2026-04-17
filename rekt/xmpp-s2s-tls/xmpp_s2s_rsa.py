"""
xmpp_s2s_rsa.py

XMPP server-to-server (S2S) federation — RSA TLS certificates.
Sources:
  - XEP-0178: SASL EXTERNAL for S2S TLS (XSF)
  - XEP-0220: Server Dialback (legacy S2S auth)
  - RFC 6120: XMPP Core
  - ejabberd configuration documentation (processone.net)
  - Prosody XMPP server documentation (prosody.im)

XMPP (Jabber) is the federated messaging protocol.
Each XMPP server has an RSA-2048 certificate for:
  1. Client-to-server TLS (c2s on port 5222)
  2. Server-to-server federation TLS (s2s on port 5269)
  3. BOSH/WebSocket HTTPS endpoints

Deployed in:
  - jabber.org, xmpp.jp, magicbroccoli.de (public federated XMPP)
  - Conversations.im, Gajim, Swift — XMPP clients that connect to federated servers
  - Cisco Jabber (enterprise XMPP on Cisco Unified Communications Manager)
  - WhatsApp (WhatsApp protocol is XMPP-derived; uses ejabberd at scale)
  - Wire, Slack (originally XMPP bridges)
  - German health sector: TI Messenger (Telematikinfrastruktur) uses XMPP federation
  - German military: BwMessenger (Bundeswehr internal messenger, uses Matrix/XMPP)

The S2S federation certificate is particularly interesting because:
  - It's verified by DANE TLSA or certificate pinning in XMPP federation
  - S2S carries inter-server message delivery between federated XMPP domains
  - For a federated XMPP deployment, every message sent between domains goes over
    S2S TLS. The RSA certificate is what authenticates the delivering server.

TI Messenger (German healthcare XMPP):
  - Used for secure messaging in the German Telematikinfrastruktur
  - Connects hospital systems, pharmacies, doctors, health insurance companies
  - Federated XMPP with RSA-2048 server certificates issued by Gematik-approved CAs
  - Patient health information transmitted over these TLS channels
"""

import ssl
import socket
import xml.etree.ElementTree as ET
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509


XMPP_S2S_PORT = 5269
XMPP_C2S_PORT = 5222

XMPP_NS_STREAM = "http://etherx.jabber.org/streams"
XMPP_NS_TLS = "urn:ietf:params:xml:ns:xmpp-tls"
XMPP_NS_SASL = "urn:ietf:params:xml:ns:xmpp-sasl"


def xmpp_s2s_connect(local_domain: str, remote_domain: str,
                      cert_path: str, key_path: str) -> ssl.SSLSocket:
    """
    Establish XMPP S2S TLS connection with RSA-2048 certificate.

    Server-to-server XMPP federation over port 5269.
    Both the local and remote servers present RSA-2048 certificates.
    XEP-0178 (SASL EXTERNAL) authenticates the server identity via the TLS
    certificate subject CN or subjectAltName.

    An attacker who factors the remote server's RSA-2048 cert can:
      - Impersonate that server to all XMPP peers it federates with
      - Intercept all federated messages to/from that domain
      - Inject messages appearing to come from users on that domain
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    # Local server's RSA-2048 cert (presented to remote server for SASL EXTERNAL)
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

    # Verify remote server's cert (from XMPP DANE or system trust store)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True

    # Look up remote server's XMPP service via SRV DNS: _xmpp-server._tcp.{domain}
    # For simplicity: direct TCP connection
    sock = socket.create_connection((remote_domain, XMPP_S2S_PORT))
    tls_sock = ctx.wrap_socket(sock, server_hostname=remote_domain)

    # The RSA-2048 certificate handshake has happened here
    # peer cert = remote server's RSA-2048 cert — use for SASL EXTERNAL
    peer_cert_der = tls_sock.getpeercert(binary_form=True)

    # Send XMPP stream header
    stream_header = f'''<?xml version="1.0"?>
<stream:stream xmlns="jabber:server"
               xmlns:stream="{XMPP_NS_STREAM}"
               from="{local_domain}"
               to="{remote_domain}"
               version="1.0">'''
    tls_sock.send(stream_header.encode('utf-8'))

    return tls_sock


def xmpp_sasl_external_auth(tls_sock: ssl.SSLSocket, local_domain: str) -> bool:
    """
    XMPP SASL EXTERNAL — authenticate server via TLS certificate (XEP-0178).

    After TLS handshake, the server sends its identity in the SASL EXTERNAL
    mechanism. The remote server verifies the certificate CN/SAN matches the
    XMPP domain. This is how S2S authentication works in properly configured
    XMPP federations.

    The RSA-2048 public key in the local server's certificate is what the
    remote server uses to verify the TLS client certificate identity.
    An attacker who factors this RSA key can authenticate as any XMPP domain.
    """
    # SASL EXTERNAL: client identity is the certificate subject
    sasl_auth = f'''<auth xmlns="{XMPP_NS_SASL}" mechanism="EXTERNAL">
    {local_domain.encode('utf-8').hex()}
</auth>'''
    tls_sock.send(sasl_auth.encode('utf-8'))

    # Server responds: <success> (authenticated) or <failure>
    response = tls_sock.recv(4096).decode('utf-8', errors='replace')
    return '<success' in response


def get_xmpp_server_cert(domain: str) -> x509.Certificate:
    """
    Retrieve XMPP server RSA-2048 certificate from S2S TLS handshake.

    This is the CRQC input — the RSA-2048 public key that authenticates
    the XMPP server to all federated peers.

    Port 5269 is open for S2S federation. Anyone can initiate a TLS
    handshake and receive the server certificate, no credentials needed.
    (The XMPP federation protocol requires the port to be openly accessible.)
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        sock = socket.create_connection((domain, XMPP_S2S_PORT), timeout=10)
        tls_sock = ctx.wrap_socket(sock, server_hostname=domain)
        cert_der = tls_sock.getpeercert(binary_form=True)
        tls_sock.close()
        return x509.load_der_x509_certificate(cert_der, default_backend())
    except Exception as e:
        return None


# TI Messenger / Gematik XMPP context:
#
# The German Telematikinfrastruktur (TI) is the national health IT network.
# Gematik mandates TI Messenger for inter-institutional healthcare communication
# from 2024 for hospitals and practices, with broader rollout planned.
#
# TI Messenger is based on Matrix (Matrix.org) but with federation to XMPP for
# certain use cases. The TLS certificates are issued by Gematik-approved CAs
# (not publicly trusted, PKI within TI).
#
# Messages on TI Messenger include:
#   - Patient referrals between doctors
#   - Lab results, imaging reports
#   - Emergency coordination between hospitals and rescue services
#   - Electronic prescriptions (eRezept) workflows
#
# An attacker who can forge the TLS cert for a TI Messenger server can:
#   - MitM healthcare messages for patients at that institution
#   - Intercept patient health information (very sensitive, GDPR Art. 9)
#   - In emergency coordination: modify or delay emergency dispatch messages
#
# Cisco Unified Communications Manager (CUCM) also uses XMPP for Cisco Jabber
# (enterprise IM) with RSA-2048 certificates. CUCM XMPP federation connects
# enterprise Jabber users to external XMPP federated servers.
# CUCM is deployed at: Fortune 500 enterprises, government agencies, DoD.
