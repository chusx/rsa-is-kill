"""
maa_client.py

Microsoft Azure Attestation (MAA) client. Submits attestation evidence
from a confidential VM and consumes the RS256 JWT that MAA returns.
Used by every Azure confidential-AI workload (confidential Copilot,
OpenAI-on-Azure with CMK-with-attestation, confidential training VMs
on NCads H100 v5).
"""

import base64
import json
import time
from typing import Optional
import requests
import jwt


MAA_REGIONAL_ENDPOINT = "https://sharedeus.eus.attest.azure.net"


def attest_sev_snp(snp_report_hex: str,
                    runtime_data: dict,
                    maa_endpoint: str = MAA_REGIONAL_ENDPOINT) -> str:
    """
    AMD SEV-SNP + (optionally) NVIDIA H100 CC report submission. MAA
    parses the SNP report, validates the AMD ASK/ARK RSA chain, cross-
    checks NVIDIA NRAS, then issues an RS256 JWT.
    """
    body = {
        "report": snp_report_hex,
        "runtimeData": {
            "data": base64.urlsafe_b64encode(
                json.dumps(runtime_data).encode()).decode().rstrip("="),
            "dataType": "JSON",
        },
    }
    r = requests.post(
        f"{maa_endpoint}/attest/SevSnpVm?api-version=2022-08-01",
        json=body, timeout=30)
    r.raise_for_status()
    return r.json()["token"]


def attest_tdx(tdx_quote_hex: str,
               runtime_data: dict,
               maa_endpoint: str = MAA_REGIONAL_ENDPOINT) -> str:
    """Intel TDX quote (DCAP v4) submission."""
    body = {
        "quote": tdx_quote_hex,
        "runtimeData": {
            "data": base64.urlsafe_b64encode(
                json.dumps(runtime_data).encode()).decode().rstrip("="),
            "dataType": "JSON",
        },
    }
    r = requests.post(
        f"{maa_endpoint}/attest/TdxVm?api-version=2023-04-01-preview",
        json=body, timeout=30)
    r.raise_for_status()
    return r.json()["token"]


def fetch_maa_jwks(maa_endpoint: str = MAA_REGIONAL_ENDPOINT) -> dict:
    """Pull MAA's JWKS (RSA-2048 signing keys) via OIDC discovery."""
    oidc = requests.get(
        f"{maa_endpoint}/.well-known/openid-configuration",
        timeout=10).json()
    jwks = requests.get(oidc["jwks_uri"], timeout=10).json()
    return jwks


def validate_maa_token(token: str,
                        expected_runtime_claims: Optional[dict] = None,
                        maa_endpoint: str = MAA_REGIONAL_ENDPOINT) -> dict:
    """
    Validate an MAA RS256 token. Returns the decoded claims dict or
    raises. This is what every downstream relying party runs before
    trusting an attestation result.
    """
    jwks = fetch_maa_jwks(maa_endpoint)
    kid = jwt.get_unverified_header(token)["kid"]
    key_entry = next(k for k in jwks["keys"] if k["kid"] == kid)
    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key_entry))

    claims = jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        issuer=maa_endpoint,
        options={"require": ["exp", "iat", "iss"]},
    )

    # MAA compliance flag: must be "azure-compliant-cvm" or similar
    compliance = claims.get("x-ms-isolation-tee", {}).get(
        "x-ms-compliance-status")
    if compliance != "azure-compliant-cvm":
        raise RuntimeError(f"MAA compliance status not ok: {compliance}")

    if expected_runtime_claims:
        rt = claims.get("x-ms-runtime", {})
        for k, v in expected_runtime_claims.items():
            if rt.get(k) != v:
                raise RuntimeError(f"runtime claim {k}: "
                                   f"expected {v}, got {rt.get(k)}")

    return claims


def attest_and_validate(evidence_hex: str,
                         tee_type: str,
                         expected_runtime_claims: dict,
                         maa_endpoint: str = MAA_REGIONAL_ENDPOINT) -> dict:
    """
    Higher-level helper. Used before releasing AI model keys / weights.
    """
    if tee_type == "TDX":
        token = attest_tdx(evidence_hex, expected_runtime_claims, maa_endpoint)
    elif tee_type == "SNP":
        token = attest_sev_snp(evidence_hex, expected_runtime_claims,
                                maa_endpoint)
    else:
        raise ValueError(f"unsupported TEE: {tee_type}")

    return validate_maa_token(token, expected_runtime_claims, maa_endpoint)
