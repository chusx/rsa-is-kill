"""
acme_rsa_account.py

ACME protocol (RFC 8555) — RSA account keys and certificate signing requests.
Source: acme.py reference; Certbot (https://github.com/certbot/certbot)

Let's Encrypt has issued certificates to 300M+ unique domains.
The ACME protocol authenticates certificate requests using the account key.
Default account key type: RSA-2048 (Certbot default until ~2021, still in use).

ACME authentication:
  1. Client signs JWS (JSON Web Signature) requests with account RSA key
  2. ACME server verifies JWS signature to authenticate account operations
  3. Client generates RSA-2048 CSR for the certificate (or ECDSA P-256)
  4. After domain validation (HTTP-01/DNS-01), server issues certificate

JWS with RSA-2048 account key uses RS256 (RSASSA-PKCS1-v1_5 with SHA-256).
The account public key is in the JWS header on every request.

Every Let's Encrypt account that was created before ~2021 defaults to RSA-2048
account keys (Certbot switched to ECDSA default in 2021 but existing accounts
keep their RSA keys). The account key is in ~/.config/letsencrypt/accounts/.

The TLS certificates issued by Let's Encrypt are not at risk directly (they're
short-lived, 90 days). But the ACCOUNT KEY is long-lived and used to authenticate
all certificate operations including revocation and renewal.
"""

import json
import base64
import hashlib
import struct
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


def b64url(data: bytes) -> str:
    """Base64url encode without padding (RFC 8555 / JWK)."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def jwk_from_rsa_key(private_key) -> dict:
    """
    Build a JWK (JSON Web Key) from an RSA-2048 private key.

    The JWK public key is included in every JWS header sent to the ACME server.
    It contains the RSA modulus (n) and public exponent (e) in base64url format.

    This is the CRQC input: a 2048-bit RSA public key in JSON, sent over HTTPS
    to the Let's Encrypt API endpoint in every ACME request.

    ACME key thumbprint (used as account identifier) = SHA-256(JWK public key JSON)
    This thumbprint is also used in the http-01 challenge response file.
    """
    pub = private_key.public_key()
    pub_numbers = pub.public_key().public_numbers()

    # n: RSA modulus (256 bytes for RSA-2048), base64url encoded
    n_bytes = pub_numbers.n.to_bytes(256, byteorder='big')
    # e: public exponent (typically 65537 = 0x010001, 3 bytes), base64url
    e_bytes = pub_numbers.e.to_bytes((pub_numbers.e.bit_length() + 7) // 8, byteorder='big')

    return {
        "kty": "RSA",
        "n": b64url(n_bytes),   # 2048-bit modulus — CRQC input
        "e": b64url(e_bytes),   # 65537 = AQAB
    }


def acme_sign_request(payload: dict, url: str, account_key, nonce: str,
                       account_url: str = None) -> dict:
    """
    Sign an ACME request with the account RSA-2048 key (JWS RS256).

    Called for every ACME API call:
      - Account registration (newAccount)
      - Order creation (newOrder)
      - Authorization requests
      - Challenge responses
      - CSR submission (finalizeOrder)
      - Certificate download

    The JWS header includes either jwk (public key) or kid (account URL),
    plus the nonce and URL for replay prevention.

    An attacker who derives the account RSA private key can:
      - Revoke all certificates on the account
      - Issue new certificates for all domains on the account
      - Modify account contact information
      - The Let's Encrypt server will accept all requests as authenticated
    """
    # Build JWS header
    if account_url:
        header = {"alg": "RS256", "nonce": nonce, "url": url, "kid": account_url}
    else:
        # New account: include full JWK public key
        header = {"alg": "RS256", "nonce": nonce, "url": url,
                  "jwk": jwk_from_rsa_key(account_key)}

    payload_b64 = b64url(json.dumps(payload).encode('utf-8')) if payload else b64url(b'')
    header_b64 = b64url(json.dumps(header, separators=(',', ':')).encode('utf-8'))

    # JWS signing input: base64url(header) + "." + base64url(payload)
    signing_input = f"{header_b64}.{payload_b64}".encode('ascii')

    # RS256 = RSASSA-PKCS1-v1_5 with SHA-256
    # This is the RSA-2048 private key operation
    signature = account_key.sign(
        signing_input,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    return {
        "protected": header_b64,
        "payload": payload_b64,
        "signature": b64url(signature),
    }


def generate_rsa_account_key(key_size: int = 2048):
    """
    Generate RSA account key for ACME registration.

    Certbot used RSA-2048 as default until 2021.
    Many existing accounts still have RSA-2048 keys.
    Some certbot configurations explicitly set --key-type rsa.

    Certbot stores account keys at:
      ~/.config/letsencrypt/accounts/acme-v02.api.letsencrypt.org/directory/
        {account_thumbprint}/private_key.json

    The key is stored as a JWK JSON file. The 'n' (modulus) field is the
    RSA-2048 public key — the CRQC input.

    Let's Encrypt also stores the account public key on their servers.
    Both copies are the same RSA-2048 public key.
    """
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )


def generate_rsa_csr(domain: str, private_key):
    """
    Generate a Certificate Signing Request (CSR) with RSA-2048 key.

    This is submitted to Let's Encrypt as part of the ACME finalize request.
    The CSR contains the RSA-2048 public key for the certificate.

    Note: The short-lived (90-day) TLS certificate's RSA key is what most
    people worry about. But the ACCOUNT KEY is the more dangerous target:
      - It's long-lived (years, until manually rotated)
      - It authorizes certificate operations for all domains on the account
      - It's stored on the client in a JSON file that may be backed up

    An attacker who factors the account RSA key can revoke/reissue certificates
    for all domains associated with that Let's Encrypt account.
    Combined with DNS control, this enables HTTPS MITM on those domains.
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(domain)]),
        critical=False
    ).sign(private_key, hashes.SHA256(), default_backend())

    return csr.public_bytes(serialization.Encoding.DER)


def acme_get_thumbprint(account_key) -> str:
    """
    Compute ACME account key thumbprint (RFC 8555 Section 8.1).

    The thumbprint is SHA-256(JWK) and serves as the account identifier.
    It's also used in HTTP-01 challenge response files.

    The JWK JSON that's hashed contains only {e, kty, n} in lexicographic order.
    The 'n' field contains the RSA-2048 modulus.
    """
    jwk = jwk_from_rsa_key(account_key)
    # Canonical JWK for thumbprint: only {e, kty, n}, sorted
    canonical = json.dumps({"e": jwk["e"], "kty": "RSA", "n": jwk["n"]},
                            separators=(',', ':'), sort_keys=True)
    return b64url(hashlib.sha256(canonical.encode('ascii')).digest())


# Let's Encrypt deployment context:
#
# Let's Encrypt has issued 2+ billion certificates since 2015.
# Currently serves 300M+ active domains.
# ~60% of the web uses HTTPS certificates from Let's Encrypt.
#
# Account keys at risk:
#   - Certbot accounts created before 2021 (default RSA-2048)
#   - Any certbot deployment with --key-type rsa (explicit RSA)
#   - Any acme.sh deployment (uses RSA by default)
#   - Any Go ACME library using RSA (e.g., golang.org/x/crypto/acme)
#   - Any custom ACME client that generates RSA account keys
#
# The Let's Encrypt API endpoint (acme-v02.api.letsencrypt.org) stores every
# registered account's public key. This is not public, but the key is also
# stored locally in the certbot account directory.
#
# Impact of account key compromise:
#   - Revoke all certificates (DoS)
#   - Issue new certificates for all domains (for MITM, requires DNS control too)
#   - The short-lived cert rotation model doesn't help here — the account key is static
