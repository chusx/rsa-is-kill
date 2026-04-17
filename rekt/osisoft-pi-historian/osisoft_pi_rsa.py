"""
osisoft_pi_historian.py

OSIsoft PI System (now AVEVA PI) — RSA certificates in PI Data Archive and AF Server.
Source: OSIsoft PI Server 2018 SP3+ security documentation; PI AF SDK; PI Web API docs.
        https://techsupport.osisoft.com/Documentation/PI-Data-Archive/

OSIsoft PI System is the dominant industrial historian and real-time data infrastructure:
  - Used by ~65% of Fortune 500 industrial companies
  - 1000+ utilities, refineries, chemical plants, pharmaceutical manufacturers
  - Processes 200M+ sensor data points daily in large deployments
  - DHS ICS-CERT has issued advisories for PI System vulnerabilities

PI System components and their RSA usage:
  - PI Data Archive: stores and serves time-series process data
  - PI Asset Framework (AF): stores asset hierarchy, event frames, analyses
  - PI Web API: REST API for PI data (uses HTTPS with RSA certificate)
  - PI Integrator for Business Analytics (Tableau, PowerBI)
  - PI Connector for OPC-UA, MQTT, RDBMS

Security model (PI Server 2018 SP3+):
  - PI Server to PI Server trust: X.509 certificates (RSA-2048)
  - PI Web API: HTTPS server certificate (RSA-2048, IIS-hosted)
  - PI AF Server: SSL/TLS for remote connections (RSA-2048)
  - PI to PI interface: RSA certificate authentication
  - PI Connector Relay: TLS with RSA-2048 client/server certificates

The PI System's "trust table" in older versions used a legacy trust mechanism
(hostname-based). Newer versions use PKI with RSA-2048 certificates.
"""

import ssl
import socket
import struct
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509


class PIServerTLSConnection:
    """
    PI Server TLS connection — RSA-2048 certificate authentication.

    The PI Data Archive server presents an RSA-2048 certificate during TLS
    handshake. PI clients (PI ProcessBook, PI DataLink, PI Web API, PI AF SDK)
    verify this certificate against the PI trust store.

    Connection: pi-client -> TCP 5450 (pinetmgr, PI Server manager)
                pi-client -> TCP 5468 (PI Web API, HTTPS)
                pi-client -> TCP 5459 (PI AF Server)

    The server certificate's RSA-2048 public key is sent in the TLS ServerHello
    on every connection. Available from any network-accessible PI server.
    """

    def __init__(self, pi_server_host: str, port: int = 5468):
        self.host = pi_server_host
        self.port = port
        self._ssl_ctx = None
        self._conn = None

    def connect_with_rsa_client_cert(self, client_cert_path: str, client_key_path: str):
        """
        Connect to PI Web API with mutual TLS (RSA-2048 client certificate).

        PI Web API supports certificate-based authentication in addition to
        Kerberos and basic auth. The client certificate CN is mapped to a PI
        identity via PI AF.

        This is used by:
          - PI Connector services (machine identity)
          - PI to PI interfaces (server-to-server)
          - External applications with certificate-based PI access
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        # Load RSA-2048 client certificate
        ctx.load_cert_chain(certfile=client_cert_path, keyfile=client_key_path)

        # Load PI trust store (contains PI Server's RSA-2048 CA cert)
        # Default: C:\ProgramData\OSIsoft\PI\Certificates\
        ctx.load_verify_locations(cafile=r"C:\ProgramData\OSIsoft\PI\Certificates\pi-ca.crt")

        self._ssl_ctx = ctx
        conn = socket.create_connection((self.host, self.port))
        self._conn = ctx.wrap_socket(conn, server_hostname=self.host)

        # TLS handshake: PI server presents RSA-2048 cert
        # Client presents RSA-2048 client cert
        return self._conn

    def get_server_rsa_cert(self) -> x509.Certificate:
        """
        Retrieve the PI server's RSA-2048 certificate from TLS handshake.

        This is the CRQC input — the RSA-2048 public key that authenticates
        the PI Data Archive server to all clients.

        Available from any TCP connection to port 5468 (PI Web API),
        no authentication required for the TLS handshake itself.
        """
        # Connect without verification to get the cert
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        conn = socket.create_connection((self.host, self.port))
        tls_conn = ctx.wrap_socket(conn, server_hostname=self.host)

        # Get DER-encoded server certificate
        cert_der = tls_conn.getpeercert(binary_form=True)
        tls_conn.close()

        return x509.load_der_x509_certificate(cert_der, default_backend())


def pi_server_to_server_auth(source_pi_server: str, target_pi_server: str,
                              source_cert_path: str, source_key_path: str) -> bool:
    """
    PI to PI interface authentication — RSA-2048 mutual TLS.

    PI to PI (PI-to-PI) is the replication interface between PI Data Archive
    servers. Used for:
      - Remote site to central historian replication
      - Disaster recovery / high availability
      - Corporate data aggregation (plant PI -> enterprise PI)

    The PI-to-PI interface uses certificate-based mutual TLS authentication.
    Both PI servers present RSA-2048 certificates and verify each other.

    An attacker who has factored either server's RSA-2048 certificate can:
      - Impersonate either PI server to the other
      - Inject false process data into the replication stream
      - Deny data to the central historian (suppress alarms, falsify readings)
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=source_cert_path, keyfile=source_key_path)
    ctx.load_verify_locations(cafile=r"C:\ProgramData\OSIsoft\PI\Certificates\pi-ca.crt")

    # TCP 5461: PI-to-PI interface (piarchss)
    conn = socket.create_connection((target_pi_server, 5461))
    tls_conn = ctx.wrap_socket(conn, server_hostname=target_pi_server)

    # Mutual TLS authentication:
    # source presents RSA-2048 cert -> target verifies -> replication authorized
    peer_cert = tls_conn.getpeercert(binary_form=True)
    tls_conn.close()
    return peer_cert is not None


# AVEVA PI (formerly OSIsoft PI) deployment context:
#
# After Schneider Electric acquired OSIsoft in 2021, the product became AVEVA PI.
# The installed base of "OSIsoft PI" systems still vastly outnumbers AVEVA PI.
# Both use the same RSA-2048 certificate infrastructure.
#
# Critical infrastructure deployments:
#   - Electric utilities: monitoring power generation, transmission, and distribution
#   - Oil and gas: refinery process monitoring (shell, BP, ExxonMobil all use PI)
#   - Nuclear power: plant process monitoring (NRC-regulated in US)
#   - Water/wastewater: treatment plant monitoring
#   - Pharmaceutical: FDA 21 CFR Part 11 audit trail (signed with PI certs)
#
# PI historian data is valuable intel:
#   - Power plant output curves -> operational patterns
#   - Refinery process conditions -> product specifications
#   - Chemical plant reaction parameters -> production secrets
#
# PI Web API (the REST interface) uses IIS with a standard Windows server cert
# (RSA-2048, from the enterprise CA or self-signed). Any HTTP client can reach it.
# The TLS certificate is the authentication layer for all PI Web API queries.
#
# PI Connector services authenticate to PI Data Archive using RSA-2048 certificates.
# These certificates are in the Windows certificate store on the connector machine.
# Their public keys are registered in PI's trust database.
#
# Factoring any of these RSA-2048 certs enables:
# 1. Impersonating a PI Connector -> injecting false process data
# 2. Impersonating a PI server -> MITM replication to get full process history
# 3. For FDA-regulated pharma: falsifying PI audit trail (21 CFR Part 11 violation)
