"""
nras_client.py

CVM-side client that:
  1. Asks the GPU driver for an attestation report.
  2. Submits the report + nonce to NRAS (NVIDIA Remote Attestation Service).
  3. Parses and validates the returned RS256 JWT.
  4. Hands the verdict to the CVM's key-release policy engine (Azure
     Managed HSM, GCP Confidential Space, HashiCorp Vault transit, etc.)
     which decides whether to release model weights / data decryption keys.

This is the same flow that runs on every AI workload start in:
  - Azure Confidential GPU (NCads H100 v5, ND MI300X v5)
  - GCP Confidential Space with H100 (private preview)
  - Oracle OCI Confidential AI
  - In-house confidential AI stacks at large enterprises
"""

import base64
import json
import os
import secrets
import requests
import jwt
from cryptography.hazmat.primitives import serialization


NRAS_URL = "https://nras.attestation.nvidia.com/v3/attest/gpu"
NRAS_JWKS_URL = "https://nras.attestation.nvidia.com/v3/.well-known/jwks.json"


class AttestationFailed(Exception):
    pass


def request_gpu_report(gpu_index: int, nonce: bytes) -> bytes:
    """
    Ask the NVIDIA GPU driver (via nvml / nvtrust Verifier SDK) to emit a
    fresh attestation report with the supplied nonce mixed into the
    signed body. Returns raw report bytes (body + signature + cert chain).
    """
    # In production: nvtrust.Verifier.get_evidence(gpu_index, nonce)
    # Uses the GPU's on-die RAE via a vendor-specific ioctl to /dev/nvidia*
    return b"<raw attestation report>"


def submit_to_nras(report: bytes, nonce: bytes) -> str:
    """Submit evidence to NRAS; receive an RS256 JWT on success."""
    resp = requests.post(
        NRAS_URL,
        json={
            "nonce": nonce.hex(),
            "evidence": base64.b64encode(report).decode(),
            "arch": "HOPPER",
        },
        headers={"Content-Type": "application/json"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["eat"]   # Entity Attestation Token (JWT)


def fetch_nras_jwks() -> dict:
    """Pull NRAS signing keys — RSA-3072 JWKS pinned at deploy time."""
    return requests.get(NRAS_JWKS_URL, timeout=10).json()


def validate_nras_jwt(eat: str,
                       expected_nonce: bytes,
                       expected_rim: str = None) -> dict:
    """
    Validate the NRAS RS256 JWT, check claim constraints, and return the
    decoded claims for the policy engine.
    """
    jwks = fetch_nras_jwks()
    kid = jwt.get_unverified_header(eat)["kid"]
    key_entry = next(k for k in jwks["keys"] if k["kid"] == kid)
    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key_entry))

    claims = jwt.decode(
        eat,
        public_key,
        algorithms=["RS256"],
        issuer="nras.attestation.nvidia.com",
        options={"require": ["exp", "iat", "nbf"]},
    )

    if claims.get("eat_nonce") != expected_nonce.hex():
        raise AttestationFailed("nonce mismatch")

    if claims.get("x-nvidia-gpu-ccmode") != "ON":
        raise AttestationFailed(
            f"GPU not in CC mode: {claims.get('x-nvidia-gpu-ccmode')}")

    if claims.get("measres") != "success":
        raise AttestationFailed(
            f"measurement result: {claims.get('measres')}")

    if expected_rim and claims.get("x-nvidia-gpu-driver-rim") != expected_rim:
        raise AttestationFailed(
            f"unexpected driver RIM: {claims.get('x-nvidia-gpu-driver-rim')}")

    return claims


def attest_and_release(gpu_index: int,
                        expected_rim: str,
                        key_release_callback) -> dict:
    """
    One-shot: produce fresh nonce, attest GPU, validate NRAS JWT, call
    the key-release callback with the validated claims. The callback
    typically unwraps customer-managed keys from Azure Managed HSM /
    GCP KMS / Vault under the attestation policy.
    """
    nonce = secrets.token_bytes(32)
    evidence = request_gpu_report(gpu_index, nonce)
    eat = submit_to_nras(evidence, nonce)
    claims = validate_nras_jwt(eat, nonce, expected_rim)

    # Policy is satisfied — release the wrapped model weights / data keys
    key_release_callback(claims)
    return claims
