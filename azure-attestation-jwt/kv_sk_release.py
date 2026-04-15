"""
kv_sk_release.py

Azure Key Vault Managed HSM — Secure Key Release (SKR) client.

SKR is the mechanism that releases wrapped AI model weight keys (or any
secret) into a confidential VM only after Azure Attestation confirms the
VM is running the expected TEE + code. This is the production path used
by OpenAI-on-Azure, Microsoft's confidential Copilot backend, and every
Azure customer doing "bring your own key" attestation for AI.

Flow:
  1. The confidential VM calls MAA (see maa_client.py), obtains an RS256 JWT.
  2. The VM calls Key Vault's /release endpoint, presenting:
       - The MAA JWT as "target" / environment attestation
       - The ID of the exportable KEK in Key Vault
  3. Key Vault evaluates its release policy (a JSON expression checking
     MAA claims — attestation URL, compliance status, product ID, MRTD /
     SNP measurement).
  4. On success, Key Vault wraps the KEK to an ephemeral public key the
     VM supplied, and returns the wrapped KEK as a signed JWE.
  5. The VM unwraps and uses the KEK to decrypt the model weight blob
     from storage.
"""

import base64
import json
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


MHSM_URL = "https://my-hsm.managedhsm.azure.net"


class ReleasePolicyViolation(Exception):
    pass


def build_release_policy(mrtd: str,
                          svn_min: int,
                          expected_attestation_url: str) -> dict:
    """
    Build a Key Vault key release policy. Stored on the key at creation
    time; evaluated server-side on every release request. Keyed against
    claims in the MAA JWT.
    """
    policy = {
        "version": "1.0.0",
        "anyOf": [{
            "authority": expected_attestation_url,
            "allOf": [
                {"claim": "x-ms-isolation-tee.x-ms-compliance-status",
                 "equals": "azure-compliant-cvm"},
                {"claim": "x-ms-isolation-tee.x-ms-attestation-type",
                 "equals": "tdxvm"},
                {"claim": "x-ms-isolation-tee.x-ms-runtime.client-payload.mrtd",
                 "equals": mrtd},
                {"claim": "x-ms-isolation-tee.x-ms-runtime.client-payload.svn",
                 "greaterOrEqual": svn_min},
            ],
        }],
    }
    return policy


def create_exportable_kek(mhsm_url: str,
                           key_name: str,
                           release_policy: dict,
                           access_token: str) -> dict:
    """
    Create an AES-256 KEK inside MHSM with `exportable=True` and the
    given release policy. The KEK itself never leaves the HSM clear —
    it is only ever released wrapped under an ephemeral RSA key.
    """
    body = {
        "kty": "oct-HSM",
        "key_size": 256,
        "key_ops": ["wrapKey", "unwrapKey", "encrypt", "decrypt"],
        "attributes": {"exportable": True},
        "release_policy": {
            "contentType": "application/json; charset=utf-8",
            "data": base64.urlsafe_b64encode(
                json.dumps(release_policy).encode()).decode().rstrip("="),
        },
    }
    r = requests.put(
        f"{mhsm_url}/keys/{key_name}/create?api-version=7.4",
        json=body,
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


def release_key(mhsm_url: str,
                 key_name: str,
                 target_attestation_jwt: str,
                 ephemeral_rsa_pubkey_jwk: dict,
                 access_token: str) -> bytes:
    """
    Request the KEK. Key Vault evaluates the key's release policy against
    the MAA JWT claims; if satisfied, returns the KEK wrapped under
    `ephemeral_rsa_pubkey_jwk` as a JWE (RSA-OAEP-256 + AES-256-GCM).
    """
    body = {
        "target": target_attestation_jwt,
        "enc": "CKM_RSA_AES_KEY_WRAP",   # KV uses RSA-OAEP+AES wrap
        "environment": ephemeral_rsa_pubkey_jwk,
    }
    r = requests.post(
        f"{mhsm_url}/keys/{key_name}/release?api-version=7.4",
        json=body,
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=30,
    )
    if r.status_code == 403:
        raise ReleasePolicyViolation(r.json())
    r.raise_for_status()
    return r.json()["value"].encode()


def unwrap_kek_inside_cvm(wrapped_jwe: bytes,
                           ephemeral_rsa_privkey: rsa.RSAPrivateKey) -> bytes:
    """
    Inside the confidential VM: unwrap the KEK using the ephemeral RSA
    private key that was never exposed outside the CVM. The KEK is then
    used to decrypt the on-disk model weight ciphertext.
    """
    # ... parse JWE header, RSA-OAEP unwrap CEK, AES-GCM decrypt KEK ...
    return b"<unwrapped AES-256 KEK>"
