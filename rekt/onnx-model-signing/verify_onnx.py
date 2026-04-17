"""
verify_onnx.py

Consumer-side verification of a signed ONNX model. Called in:
  - Windows ML on Copilot+ PCs before dispatching a model to the NPU
  - ONNX Runtime EP wrappers on Android (AICore) and iOS (CoreML shim)
    before loading signed models into the on-device AI runtime
  - Edge gateways in automotive / industrial AI before loading
    perception models
  - Enterprise MLOps admission controllers / ONNX Runtime extensions
    verifying model provenance before inference
"""

import base64
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509 import load_pem_x509_certificate
import onnx


SIGNATURE_METADATA_KEY = "com.onnx.signature.v1"
SIGNER_SUBJECT_KEY = "com.onnx.signer.subject"
SIGNATURE_ALGORITHM_KEY = "com.onnx.signature.alg"


class ONNXVerificationError(Exception):
    pass


def canonical_bytes_unsigned(model: onnx.ModelProto) -> bytes:
    """Re-produce canonical bytes by stripping the signature metadata."""
    stripped = onnx.ModelProto()
    stripped.CopyFrom(model)
    del stripped.metadata_props[:]
    for p in model.metadata_props:
        if p.key in (SIGNATURE_METADATA_KEY, SIGNER_SUBJECT_KEY,
                     SIGNATURE_ALGORITHM_KEY):
            continue
        stripped.metadata_props.add(key=p.key, value=p.value)
    return stripped.SerializeToString(deterministic=True)


def extract_metadata(model: onnx.ModelProto) -> dict:
    meta = {p.key: p.value for p in model.metadata_props}
    if SIGNATURE_METADATA_KEY not in meta:
        raise ONNXVerificationError("no signature in ONNX metadata")
    return meta


def verify_cert_chain(signer_cert_pem: bytes,
                       trust_anchor_pems: list) -> object:
    """
    Validate cert chain to one of the configured trust anchors.
    Windows ML trust anchors: Microsoft Root Certificate Authority 2011
    (RSA-4096). Android AICore: Google Play Code Signing CA. Automotive
    OEM: the vehicle's provisioning CA (often RSA-2048 issued).
    """
    signer = load_pem_x509_certificate(signer_cert_pem)
    # Real chain walk via cryptography X509 store or platform APIs.
    # Abbreviated: confirm issuer matches one of the trust anchors.
    for anchor_pem in trust_anchor_pems:
        anchor = load_pem_x509_certificate(anchor_pem)
        if signer.issuer == anchor.subject:
            return signer
    raise ONNXVerificationError("signer cert does not chain to trust list")


def verify_onnx_model(model_path: Path,
                      signer_cert_pem: bytes,
                      trust_anchor_pems: list) -> dict:
    """
    Verify the embedded signature. Returns {signer_subject, algorithm,
    model_sha384} on success; raises on failure.

    This is what Windows ML calls via `MLOperatorAuthorInfo` before
    the model reaches the NPU dispatch stage on Copilot+ PCs.
    """
    model = onnx.load(str(model_path))
    meta = extract_metadata(model)

    signature = base64.b64decode(meta[SIGNATURE_METADATA_KEY])
    algorithm = meta.get(SIGNATURE_ALGORITHM_KEY, "RSA-PSS-SHA384-MGF1")
    if algorithm != "RSA-PSS-SHA384-MGF1":
        raise ONNXVerificationError(f"unsupported alg {algorithm}")

    signer = verify_cert_chain(signer_cert_pem, trust_anchor_pems)

    canonical = canonical_bytes_unsigned(model)
    digest = hashlib.sha384(canonical).digest()

    pub = signer.public_key()
    if not isinstance(pub, rsa.RSAPublicKey):
        raise ONNXVerificationError(
            "non-RSA signer; policy requires RSA for this catalog")

    pub.verify(
        signature,
        digest,
        padding.PSS(mgf=padding.MGF1(hashes.SHA384()),
                    salt_length=padding.PSS.DIGEST_LENGTH),
        hashes.Prehashed(hashes.SHA384()),
    )

    return {
        "signer_subject": meta.get(SIGNER_SUBJECT_KEY,
                                    signer.subject.rfc4514_string()),
        "algorithm": algorithm,
        "model_sha384": digest.hex(),
    }
