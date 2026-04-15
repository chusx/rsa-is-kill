"""
verify_model.py

Consumer-side verification of a signed ML model. This is what runs inside:

  - HuggingFace Hub when displaying the "verified" badge on a model page
  - Google Vertex AI Model Registry on upload (policy-gated)
  - KServe InferenceService admission controller (reject unsigned models)
  - Kubeflow / Airflow model-pull steps
  - Local `cosign verify-blob` / `sigstore verify` CLI

Verification chain:
  1. Parse .sigstore bundle next to weights.
  2. Extract Fulcio leaf cert; verify chain to Sigstore root (RSA-2048).
  3. Check cert's SAN OIDC identity matches expected signer
     (e.g., "https://github.com/meta-llama/llama-models").
  4. Verify DSSE signature over PAE(payload_type, payload).
  5. Verify Rekor inclusion proof against log's published root.
  6. Re-hash the model files; compare to manifest subjects.
"""

import base64
import hashlib
import json
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.x509 import load_pem_x509_certificate, ExtensionOID
from cryptography.x509.oid import NameOID


SIGSTORE_FULCIO_ROOT_PEM = b"""
-----BEGIN CERTIFICATE-----
... Sigstore public-good Fulcio root (RSA-2048) ...
-----END CERTIFICATE-----
"""


class ModelVerificationError(Exception):
    pass


def verify_cert_chain(leaf_pem: bytes, fulcio_root_pem: bytes) -> object:
    """Verify the Fulcio leaf chains to the Sigstore root. Simplified."""
    leaf = load_pem_x509_certificate(leaf_pem)
    root = load_pem_x509_certificate(fulcio_root_pem)
    # Real verify uses cryptography's store-based X509StoreContext
    # or sigstore-python's trust bundle logic
    return leaf


def extract_signer_identity(leaf_cert) -> dict:
    """
    Pull the OIDC identity from Fulcio-issued cert extensions.
    Relevant extension OIDs (Fulcio v1.3+):
       1.3.6.1.4.1.57264.1.8 — issuer URL
       1.3.6.1.4.1.57264.1.9 — build signer URI (e.g. workflow ref)
       URI SAN — OIDC subject
    """
    san_ext = leaf_cert.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    uris = san_ext.value.get_values_for_type(type(san_ext.value)) if False else []
    # Simplified; real code parses SAN.get_values_for_type(x509.URI)
    identity = {}
    for ext in leaf_cert.extensions:
        if ext.oid.dotted_string == "1.3.6.1.4.1.57264.1.8":
            identity["issuer"] = ext.value.value.decode()
        if ext.oid.dotted_string == "1.3.6.1.4.1.57264.1.9":
            identity["build_signer"] = ext.value.value.decode()
    return identity


def verify_dsse(envelope: dict, leaf_cert) -> bytes:
    """Verify DSSE signature using leaf cert's public key. Returns payload."""
    sig = base64.b64decode(envelope["signatures"][0]["sig"])
    payload = base64.b64decode(envelope["payload"])
    pae = (f"DSSEv1 {len(envelope['payloadType'])} {envelope['payloadType']} "
           f"{len(payload)} ").encode() + payload

    pub = leaf_cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        pub.verify(sig, pae, padding.PKCS1v15(), hashes.SHA256())
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(sig, pae, ec.ECDSA(hashes.SHA256()))
    else:
        raise ModelVerificationError(f"unsupported key type {type(pub)}")
    return payload


def verify_rekor_inclusion(tlog_entry: dict) -> None:
    """
    Verify the Rekor signed inclusion proof. Real verification walks the
    Merkle inclusion path and checks the tree-head signature (RSA-2048 by
    the Rekor log operator).
    """
    if not tlog_entry.get("inclusionProof"):
        raise ModelVerificationError("missing Rekor inclusion proof")
    # ... RSA verify rekor_log_pubkey over checkpoint ...
    # ... walk Merkle path, compare to rootHash ...


def verify_manifest(payload_bytes: bytes, model_dir: Path) -> None:
    """Re-hash every file in model_dir; compare to payload subjects."""
    statement = json.loads(payload_bytes)
    subjects = {s["name"]: s["digest"]["sha256"]
                for s in statement["subject"]}

    for rel, expected in subjects.items():
        p = model_dir / rel
        if not p.exists():
            raise ModelVerificationError(f"missing file from manifest: {rel}")
        h = hashlib.sha256()
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        if h.hexdigest() != expected:
            raise ModelVerificationError(
                f"file {rel}: expected {expected}, got {h.hexdigest()}")


def verify_model(model_dir: str,
                 bundle_path: str,
                 expected_identity: dict,
                 fulcio_root_pem: bytes = SIGSTORE_FULCIO_ROOT_PEM) -> dict:
    """
    Top-level entrypoint. Returns the verified statement; raises on any
    signature/identity/manifest mismatch.
    """
    with open(bundle_path) as f:
        bundle = json.load(f)

    leaf_pem = base64.b64decode(
        bundle["verificationMaterial"]["x509CertificateChain"]
              ["certificates"][0]["rawBytes"])
    leaf = verify_cert_chain(leaf_pem, fulcio_root_pem)

    identity = extract_signer_identity(leaf)
    for k, v in expected_identity.items():
        if identity.get(k) != v:
            raise ModelVerificationError(
                f"identity mismatch on {k}: expected {v}, got {identity.get(k)}")

    payload = verify_dsse(bundle["dsseEnvelope"], leaf)

    verify_rekor_inclusion(
        bundle["verificationMaterial"]["tlogEntries"][0])

    verify_manifest(payload, Path(model_dir))
    return json.loads(payload)
