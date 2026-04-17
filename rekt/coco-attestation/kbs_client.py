"""
kbs_client.py

Attestation Agent (AA) client for CoCo Trustee KBS. This is the in-guest
component inside every Confidential Containers pod that pulls secrets
(AI model keys, customer training data keys, TLS certs for inference
endpoints) from KBS after attestation succeeds.

Reference: confidential-containers/guest-components (aa + kbc), spec at
https://github.com/confidential-containers/trustee/blob/main/kbs/docs/.
"""

import base64
import json
import os
import ssl
import hashlib
from typing import Optional
import requests


class KBSClient:
    """
    Minimal KBS client implementing the "kbs_protocol" handshake.

    1. AA -> KBS POST /auth with AA challenge request
       KBS -> AA returns challenge (nonce)
    2. AA -> KBS POST /attest with TEE evidence bound to nonce
       KBS -> AS verifies; AS returns token; KBS returns cookie with
       Attestation Result token (RS256) bound to session
    3. AA -> KBS GET /resource/{repo}/{type}/{tag}
       KBS evaluates Resource Policy against token claims, returns
       JWE-wrapped resource bytes (e.g., AES key for model-weights
       decryption)
    """

    def __init__(self, kbs_url: str, ca_cert_pem: bytes):
        self.kbs_url = kbs_url
        # Trust only the pinned KBS CA (RSA-2048 issuing KBS server certs)
        self.session = requests.Session()
        self.session.verify = self._write_ca_bundle(ca_cert_pem)

    @staticmethod
    def _write_ca_bundle(pem: bytes) -> str:
        path = "/run/kbs-ca.pem"
        with open(path, "wb") as f:
            f.write(pem)
        return path

    def auth(self, tee_type: str) -> dict:
        """First phase: get an attestation challenge."""
        r = self.session.post(f"{self.kbs_url}/kbs/v0/auth",
                              json={"version": "0.1.0", "tee": tee_type},
                              timeout=30)
        r.raise_for_status()
        return r.json()   # contains nonce + extra-params

    def attest(self, tee_evidence_b64: str, nonce: str,
                tee_type: str) -> dict:
        """
        Second phase: submit evidence; receive a KBS-issued token (RS256)
        in a Set-Cookie and attestation-result JSON.
        """
        body = {
            "tee-pubkey": self._ephemeral_rsa_jwk_pub(),
            "tee-evidence": json.dumps({
                "tee": tee_type,
                "evidence": tee_evidence_b64,
                "nonce": nonce,
            }),
        }
        r = self.session.post(f"{self.kbs_url}/kbs/v0/attest",
                              json=body, timeout=60)
        r.raise_for_status()
        return {
            "attestation_result": r.json(),
            "session_cookie": r.cookies.get("kbs-session-id"),
        }

    def get_resource(self, resource_path: str) -> bytes:
        """
        Third phase: request a resource. Path convention:
        `/kbs/v0/resource/<repo>/<type>/<tag>`, e.g.
        `/kbs/v0/resource/openai/whisper-large-v3/key-v1`.
        """
        r = self.session.get(f"{self.kbs_url}/kbs/v0/resource/{resource_path}",
                             timeout=30)
        r.raise_for_status()
        jwe = r.content
        return self._unwrap_jwe(jwe)

    def _ephemeral_rsa_jwk_pub(self) -> dict:
        """
        Generate an in-TEE ephemeral RSA keypair; return the JWK
        public key. KBS will use this to JWE-wrap resources so only
        this TEE instance can decrypt them.
        """
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        k = rsa.generate_private_key(65537, 2048)
        self._rsa_private = k
        nums = k.public_key().public_numbers()
        return {
            "kty": "RSA",
            "alg": "RSA-OAEP-256",
            "use": "enc",
            "n": base64.urlsafe_b64encode(
                nums.n.to_bytes(256, "big")).decode().rstrip("="),
            "e": "AQAB",
        }

    def _unwrap_jwe(self, jwe: bytes) -> bytes:
        """Unwrap JWE using the ephemeral RSA private key."""
        # ... standard JWE RSA-OAEP-256 + A256GCM unwrap against
        # self._rsa_private; omitted for brevity.
        return b"<resource plaintext>"


def bootstrap_pod_secrets(tee_type: str,
                           evidence_b64: str,
                           kbs_url: str,
                           ca_pem: bytes,
                           resources: list) -> dict:
    """
    Called by the Attestation Agent entrypoint inside a CoCo pod. For
    each configured resource (model weight keys, data encryption keys,
    inference-endpoint TLS cert), fetch from KBS and place in the
    pod's secret tmpfs.
    """
    kbs = KBSClient(kbs_url, ca_pem)
    auth = kbs.auth(tee_type)
    kbs.attest(evidence_b64, auth["nonce"], tee_type)

    out = {}
    for r in resources:
        out[r] = kbs.get_resource(r)
        secret_path = f"/run/kata-containers/secret/{r.replace('/', '_')}"
        with open(secret_path, "wb") as f:
            f.write(out[r])
        os.chmod(secret_path, 0o400)
    return out
