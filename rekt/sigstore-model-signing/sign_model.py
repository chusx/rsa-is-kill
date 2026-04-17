"""
sign_model.py

Producer-side: sign a multi-shard ML model checkpoint using the
OpenSSF model-signing v1 flow (Sigstore Fulcio + Rekor).

Flow (per model-signing spec):
  1. Walk the model directory; hash every file (safetensors shards,
     tokenizer.json, config.json, model card).
  2. Build a manifest dict: {filename: sha256hex} across the tree.
  3. Write a DSSE envelope (Dead Simple Signing Envelope, in-toto) with
     payloadType "application/vnd.dev.sigstore.model-signing.v1+json".
  4. Obtain a Fulcio cert (RSA-2048 or ECDSA-P256 leaf, 10-minute validity)
     by presenting an OIDC token.
  5. Sign the DSSE payload using the private key paired with the Fulcio cert.
  6. Post the signature to Rekor; embed the inclusion proof in the bundle.
  7. Write `<model>/model.sig` sigstore bundle alongside the weights.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def hash_tree(model_dir: Path) -> dict:
    """Walk the model directory; SHA-256 every file. Deterministic order."""
    manifest = {}
    for path in sorted(model_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(model_dir).as_posix()
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        manifest[rel] = h.hexdigest()
    return manifest


def build_dsse_payload(manifest: dict,
                       predicate_type: str = "https://model-signing.sigstore.dev/v1") -> bytes:
    """
    Build the DSSE PAE (Pre-Authentication Encoding) payload.
    PAE("application/vnd.dev.sigstore.model-signing.v1+json", payload) is
    what actually gets signed (per DSSE spec).
    """
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {"name": name, "digest": {"sha256": digest}}
            for name, digest in manifest.items()
        ],
        "predicateType": predicate_type,
        "predicate": {
            "manifestVersion": 1,
            "fileCount": len(manifest),
        },
    }
    return json.dumps(statement, sort_keys=True).encode()


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE PAE encoding: 'DSSEv1' SP LEN(type) SP type SP LEN(payload) SP payload."""
    return (f"DSSEv1 {len(payload_type)} {payload_type} "
            f"{len(payload)} ").encode() + payload


def sign_with_fulcio_cert(payload_pae: bytes,
                           fulcio_rsa_privkey: rsa.RSAPrivateKey,
                           fulcio_cert_pem: bytes) -> dict:
    """
    Produce a DSSE envelope signed by a Fulcio-issued RSA-2048 cert.
    Most open-source Sigstore deployments default to RSA; the signing
    fleets at e.g. internal Google Sigstore are predominantly RSA.
    """
    signature = fulcio_rsa_privkey.sign(
        payload_pae,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    return {
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(payload_pae).decode(),
        "signatures": [{
            "keyid": "",
            "sig": base64.b64encode(signature).decode(),
            "cert": base64.b64encode(fulcio_cert_pem).decode(),
        }],
    }


def submit_to_rekor(dsse_envelope: dict, rekor_url: str) -> dict:
    """
    POST the DSSE envelope to Rekor's /api/v1/log/entries, receive a
    signed inclusion proof. Real implementation uses sigstore-python /
    cosign; this is structural only.
    """
    # inclusion_proof = rekor_client.log_entry(envelope=dsse_envelope)
    return {
        "logIndex": 123456789,
        "logID": "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
        "integratedTime": 1733000000,
        "inclusionProof": {
            "checkpoint": "rekor.sigstore.dev - 2605736670972794746\n...",
            "hashes": ["..."],
            "rootHash": "...",
            "treeSize": 42,
        },
    }


def sign_model(model_dir: str,
               fulcio_rsa_privkey: rsa.RSAPrivateKey,
               fulcio_cert_pem: bytes,
               rekor_url: str = "https://rekor.sigstore.dev",
               output_bundle: str = None) -> str:
    """
    End-to-end model signing. Produces a .sigstore bundle next to the
    model files. This bundle is what HuggingFace, KServe, Vertex AI,
    and NGC verify before deploying a model.
    """
    model_path = Path(model_dir)
    manifest = hash_tree(model_path)

    payload = build_dsse_payload(manifest)
    pae = dsse_pae("application/vnd.in-toto+json", payload)

    envelope = sign_with_fulcio_cert(pae, fulcio_rsa_privkey, fulcio_cert_pem)
    log_entry = submit_to_rekor(envelope, rekor_url)

    bundle = {
        "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
        "verificationMaterial": {
            "x509CertificateChain": {
                "certificates": [
                    {"rawBytes": base64.b64encode(fulcio_cert_pem).decode()}
                ],
            },
            "tlogEntries": [log_entry],
        },
        "dsseEnvelope": envelope,
    }

    out = output_bundle or os.path.join(model_dir, "model.sigstore")
    with open(out, "w") as f:
        json.dump(bundle, f, indent=2)
    return out
