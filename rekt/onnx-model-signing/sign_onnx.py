"""
sign_onnx.py

Producer-side signing of an ONNX model. Used by:
  - Azure ML Model Registry registration pipeline
  - Microsoft's Windows ML / Copilot+ PC model publishing pipeline
  - Apple's coremltools ONNX->CoreML conversion pipeline
  - Enterprise MLOps (Databricks MLflow, Vertex AI upload) producing
    signed ONNX artifacts before pushing to a model registry
  - OEM automotive tooling packaging ONNX perception models for in-vehicle
    neural accelerators
"""

import hashlib
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
import onnx


SIGNATURE_METADATA_KEY = "com.onnx.signature.v1"
SIGNER_SUBJECT_KEY = "com.onnx.signer.subject"
SIGNATURE_ALGORITHM_KEY = "com.onnx.signature.alg"


def canonical_bytes(model: onnx.ModelProto) -> bytes:
    """
    Produce a canonical byte representation for signing: clone the
    model, strip any existing signature metadata, then serialize
    deterministically.

    protobuf serialization isn't deterministic in all implementations,
    so production signers use protobuf-canonical-form libraries or
    sort map entries before serialization. Here: stripped + standard
    serialization.
    """
    stripped = onnx.ModelProto()
    stripped.CopyFrom(model)
    del stripped.metadata_props[:]
    for p in model.metadata_props:
        if p.key in (SIGNATURE_METADATA_KEY, SIGNER_SUBJECT_KEY,
                     SIGNATURE_ALGORITHM_KEY):
            continue
        stripped.metadata_props.add(key=p.key, value=p.value)
    return stripped.SerializeToString(deterministic=True)


def sign_onnx_model(model_path: Path,
                     private_key: rsa.RSAPrivateKey,
                     signer_cert_pem: bytes,
                     signer_subject: str,
                     output_path: Path = None) -> Path:
    """
    Sign an ONNX model with RSA-PSS-SHA384. Embeds:
      - base64 signature in metadata_props["com.onnx.signature.v1"]
      - signer subject (X.509 DN) for display
      - algorithm identifier for forward compatibility
    Also writes a detached `.sig` file containing a PKCS#7 signature
    over the canonical bytes (consumed by Windows ML / signtool).
    """
    model = onnx.load(str(model_path))
    canonical = canonical_bytes(model)

    digest = hashlib.sha384(canonical).digest()
    signature = private_key.sign(
        digest,
        padding.PSS(mgf=padding.MGF1(hashes.SHA384()),
                    salt_length=padding.PSS.DIGEST_LENGTH),
        hashes.Prehashed(hashes.SHA384()),
    )

    import base64
    model.metadata_props.add(
        key=SIGNATURE_METADATA_KEY,
        value=base64.b64encode(signature).decode())
    model.metadata_props.add(
        key=SIGNER_SUBJECT_KEY, value=signer_subject)
    model.metadata_props.add(
        key=SIGNATURE_ALGORITHM_KEY, value="RSA-PSS-SHA384-MGF1")

    output_path = output_path or model_path
    onnx.save(model, str(output_path))

    # Detached PKCS#7 .sig file for Windows ML / signtool consumers
    sig_path = output_path.with_suffix(output_path.suffix + ".sig")
    signer_cert = _load_cert(signer_cert_pem)
    pkcs7_sig = (pkcs7.PKCS7SignatureBuilder()
                 .set_data(canonical)
                 .add_signer(signer_cert, private_key, hashes.SHA384())
                 .sign(encoding=None, options=[pkcs7.PKCS7Options.DetachedSignature]))
    sig_path.write_bytes(pkcs7_sig)

    return output_path


def _load_cert(pem: bytes):
    from cryptography.x509 import load_pem_x509_certificate
    return load_pem_x509_certificate(pem)


if __name__ == "__main__":
    # Typical CI step in a Windows ML / Azure ML publishing pipeline:
    # load the ONNX from training, sign with the fleet's RSA key, push.
    from cryptography.hazmat.primitives import serialization

    with open("/etc/winml/publishing.key.pem", "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    with open("/etc/winml/publishing.cert.pem", "rb") as f:
        cert_pem = f.read()

    signed = sign_onnx_model(
        Path("/tmp/phi-silica-npu-int4.onnx"),
        key, cert_pem,
        signer_subject="CN=Microsoft Windows ML Publisher, O=Microsoft Corporation",
    )
    print(f"signed: {signed}")
