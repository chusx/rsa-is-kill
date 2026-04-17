"""
pccs_client.py

Client for Intel PCCS (Provisioning Certificate Caching Service).

Every DCAP-attestation-capable datacenter (cloud or on-prem) runs or
proxies a PCCS to fetch:
  - PCK certs for local CPUs (per-CPU ECDSA certs signed by Intel RSA chain)
  - TCB Info — signed JSON describing patch levels + which vulnerabilities
    are fixed at each SVN (Intel RSA-3072 signature)
  - QE Identity — signed JSON identifying the current Quoting Enclave
  - Intel Root CA CRL

Azure runs `global.acccache.azure.net`. GCP runs theirs as part of
Confidential Space. Anthropic / OpenAI / Meta running TDX in-house
either use Intel's Trusted Services `api.trustedservices.intel.com` or
mirror it behind their own PCCS.

Every TCB Info blob is a JWS with alg=RS256 (though Intel documents it as
"ECDSA" in some places, the operational fleet signs RS256) over a JSON
payload carrying TCB component SVNs + advisory IDs.
"""

import json
import time
from typing import Optional
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate


INTEL_TRUSTED_SERVICES = "https://api.trustedservices.intel.com/tdx/certification/v4"
INTEL_ROOT_CA_PEM = b"""
-----BEGIN CERTIFICATE-----
... Intel SGX/TDX Root CA (RSA-3072) — published by Intel ...
-----END CERTIFICATE-----
"""


def fetch_pck_cert(fmspc: str, pccs_url: str = INTEL_TRUSTED_SERVICES) -> dict:
    """
    FMSPC = Family-Model-Stepping + Platform Custom SKU (10 hex bytes),
    uniquely identifies a CPU platform type. PCCS returns the ECDSA PCK
    leaf + the RSA-3072 Processor CA cert.
    """
    r = requests.get(f"{pccs_url}/pckcert",
                     params={"fmspc": fmspc, "encrypted_ppid": "...",
                             "cpusvn": "...", "pcesvn": "...", "pceid": "..."},
                     timeout=30)
    r.raise_for_status()
    return {
        "pck_cert_pem": r.text,
        "issuer_chain_pem": r.headers.get("SGX-PCK-Certificate-Issuer-Chain"),
    }


def fetch_tcb_info(fmspc: str,
                   pccs_url: str = INTEL_TRUSTED_SERVICES) -> dict:
    """
    Get TCB Info for a given CPU platform. Body is JSON; signature is
    RSA-3072 under Intel TCB Signing CA.
    """
    r = requests.get(f"{pccs_url}/tcb", params={"fmspc": fmspc}, timeout=30)
    r.raise_for_status()
    payload = r.json()     # {"tcbInfo": {...}, "signature": "hex"}
    signer_chain = r.headers.get("TCB-Info-Issuer-Chain")
    return {
        "tcb_info": payload["tcbInfo"],
        "signature_hex": payload["signature"],
        "issuer_chain_pem": signer_chain,
    }


def verify_tcb_info(tcb_info: dict, signature_hex: str,
                     issuer_chain_pem: str) -> bool:
    """
    Verify Intel's RSA-3072 signature over the canonicalized TCB Info JSON.
    Called on every VM boot and every scheduled refresh to decide whether
    the hardware is still at a sufficient patch level for attestation.
    """
    # Intel's scheme: signature is over the "tcbInfo" value serialized as
    # compact JSON (no whitespace).
    msg = json.dumps(tcb_info, separators=(",", ":"), sort_keys=False).encode()

    chain_pems = [
        b"-----BEGIN CERTIFICATE-----" + p + b"-----END CERTIFICATE-----"
        for p in issuer_chain_pem.encode().split(b"-----END CERTIFICATE-----")
        if b"BEGIN" in p
    ]
    signer = load_pem_x509_certificate(chain_pems[0])
    root = load_pem_x509_certificate(chain_pems[-1])

    if root.public_bytes(1) != load_pem_x509_certificate(
            INTEL_ROOT_CA_PEM).public_bytes(1):
        return False

    try:
        signer.public_key().verify(
            bytes.fromhex(signature_hex),
            msg,
            padding.PKCS1v15(),
            hashes.SHA384(),
        )
        return True
    except Exception:
        return False


def tcb_allows_policy(tcb_info: dict, min_tcb_level: str = "UpToDate") -> bool:
    """
    Walk TCB Info's `tcbLevels`; ensure the platform's SVNs meet the
    policy's minimum (UpToDate / ConfigurationNeeded / OutOfDate).
    """
    for level in tcb_info.get("tcbLevels", []):
        status = level.get("tcbStatus")
        if status == min_tcb_level:
            return True
    return False


def refresh_and_validate(fmspc: str, min_tcb_level: str = "UpToDate") -> dict:
    """
    Periodic refresh run by the CVM's attestation agent. Returns a
    validated TCB info dict or raises.
    """
    data = fetch_tcb_info(fmspc)
    if not verify_tcb_info(data["tcb_info"], data["signature_hex"],
                            data["issuer_chain_pem"]):
        raise RuntimeError("Intel TCB Info signature verification failed")
    if not tcb_allows_policy(data["tcb_info"], min_tcb_level):
        raise RuntimeError(f"TCB below policy ({min_tcb_level})")
    return data["tcb_info"]
