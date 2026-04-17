"""
Factor the Cyrus IMAP server's RSA-2048 TLS certificate, MitM IMAPS connections
to the German federal Kolab/Cyrus deployment, and intercept ministerial email
from the BSI-approved email infrastructure.
"""

import sys, hashlib
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

CYRUS_DEFAULT_CIPHER = "HIGH:!aNULL:!MD5"
IMAPS_PORT = 993
LMTP_PORT = 24


def extract_imap_tls_cert(imap_host: str, port: int = IMAPS_PORT) -> bytes:
    """Extract the Cyrus IMAP server's RSA-2048 cert from the TLS handshake."""
    print(f"    IMAPS connect to {imap_host}:{port}")
    print("    cert from ServerHello: RSA-2048")
    print("    loaded from tls_cert_file in imapd.conf")
    return b"-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----\n"


def factor_imap_cert(cert_pem: bytes) -> bytes:
    factorer = PolynomialFactorer()
    return factorer.privkey_from_cert_pem(cert_pem)


def mitm_imaps(server_ip: str, client_ip: str, forged_key: bytes):
    """MitM an IMAPS connection between mail client and Cyrus server."""
    print(f"    intercepting IMAPS from {client_ip} to {server_ip}:{IMAPS_PORT}")
    print("    presenting forged server cert — client trusts it")
    print("    IMAP commands proxied transparently:")
    print("      1 LOGIN user@kolab.bund.de ********")
    print("      2 SELECT INBOX")
    print("      * 47 EXISTS")
    print("      3 FETCH 1:47 (BODY[])")
    print("    all messages intercepted in cleartext")


def mitm_sync_replication(primary: str, replica: str, forged_key: bytes):
    """MitM Cyrus sync_client replication between primary and replica."""
    print(f"    intercepting sync replication {primary} -> {replica}")
    print("    sync_client uses TLS with same RSA cert")
    print("    full mailbox replication stream captured")


def forge_sasl_external_client(user: str, forged_ca_key: bytes) -> bytes:
    """Forge a client certificate for SASL EXTERNAL auth over IMAP TLS."""
    print(f"    issuing client cert for: {user}")
    print("    SASL EXTERNAL: cert DN maps to IMAP mailbox")
    return b"FORGED_CLIENT_CERT"


if __name__ == "__main__":
    print("[*] Cyrus IMAP / Kolab TLS certificate attack")
    server = "mail.kolab.bund.de"

    print(f"[1] extracting TLS cert from {server}")
    cert = extract_imap_tls_cert(server)
    print("    Kolab + Cyrus: BSI-approved Exchange replacement")
    print("    deployed by German federal ministries + Bundeswehr")

    print("[2] factoring Cyrus IMAP RSA-2048 TLS cert")
    factorer = PolynomialFactorer()
    print("    tls_init_serverengine() loads this key at startup")
    print("    p, q recovered — IMAP server identity compromised")

    print("[3] MitM IMAPS: intercepting ministerial email")
    mitm_imaps(server, "10.0.5.100", b"FORGED_KEY")

    print("[4] MitM sync replication: capturing full mailbox mirror")
    mitm_sync_replication(server, "mail-replica.kolab.bund.de", b"FORGED_KEY")

    print("[5] forging SASL EXTERNAL client cert for arbitrary user")
    client_cert = forge_sasl_external_client("minister@kolab.bund.de", b"CA_KEY")
    print("    IMAP LOGIN as minister — full mailbox access")

    print("[6] impact:")
    print("    - German federal email: ministerial correspondence")
    print("    - Bundeswehr internal communications")
    print("    - Swiss Federal Administration (also Kolab)")
    print("    - BSI TR-03116 TLS guidelines don't mandate non-RSA for IMAP")
    print("    - hundreds of university Cyrus deployments (CMU, academic IMAP)")
    print("[*] Cyrus depends on OpenSSL; no non-RSA stable support")
    print("[*] imapd.conf tls_cert_file expects RSA or ECDSA PEM only")
