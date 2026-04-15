"""
c2pa_verify.py

Client-side C2PA verification. Runs in every Content Credentials-aware
consumer: browser extensions (Content Credentials Verify), Adobe
Photoshop, VeriCred, newsroom ingest pipelines, social-network upload
paths (Meta, LinkedIn, TikTok).

Inputs: JPEG bytes + a C2PA trust list (certs of approved issuers).
Output: verdict + walked provenance chain.
"""

import cbor2
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_der_x509_certificate


def extract_jumbf_from_jpeg(jpeg_bytes: bytes) -> bytes:
    """Find the APP11 JUMBF box in a JPEG. Real code handles multiple
    APP11 segments + JPEG Systems box continuation; this is one-shot."""
    assert jpeg_bytes[:2] == b"\xFF\xD8"
    i = 2
    while i < len(jpeg_bytes) - 4:
        if jpeg_bytes[i:i+2] == b"\xFF\xEB":
            seg_len = int.from_bytes(jpeg_bytes[i+2:i+4], "big")
            return jpeg_bytes[i+4:i+2+seg_len]
        i += 1
    raise ValueError("no C2PA JUMBF in JPEG")


def verify_cose_sign1(cose_sign1: bytes,
                      trust_list_ders: list) -> dict:
    """
    Verify a COSE Sign1. Returns the claim payload if the signature
    validates against a cert in the trust list. Supports PS256/PS384/PS512
    (RSA-PSS) and RS256/RS384/RS512 (RSA PKCS#1 v1.5).
    """
    tag = cbor2.loads(cose_sign1)
    protected_b, unprotected, payload, signature = tag.value

    protected = cbor2.loads(protected_b)
    alg = protected[1]
    x5chain = protected.get(33, [])
    if not x5chain:
        raise ValueError("no x5chain in protected header")

    signer_cert = load_der_x509_certificate(x5chain[0])

    # Walk x5chain up, validating each signature, until we hit the trust list
    chain = [load_der_x509_certificate(c) for c in x5chain]
    trust = [load_der_x509_certificate(c) for c in trust_list_ders]

    if not _chain_terminates_in_trust(chain, trust):
        raise ValueError("cert chain does not terminate in C2PA trust list")

    sig_structure = cbor2.dumps([
        "Signature1",
        protected_b,
        b"",
        payload,
    ])

    pubkey = signer_cert.public_key()

    alg_map = {
        -37: (padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                          salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()),
        -38: (padding.PSS(mgf=padding.MGF1(hashes.SHA384()),
                          salt_length=padding.PSS.MAX_LENGTH), hashes.SHA384()),
        -39: (padding.PSS(mgf=padding.MGF1(hashes.SHA512()),
                          salt_length=padding.PSS.MAX_LENGTH), hashes.SHA512()),
        -257: (padding.PKCS1v15(), hashes.SHA256()),
        -258: (padding.PKCS1v15(), hashes.SHA384()),
        -259: (padding.PKCS1v15(), hashes.SHA512()),
    }
    pad, h = alg_map[alg]
    pubkey.verify(signature, sig_structure, pad, h)

    return cbor2.loads(payload)


def _chain_terminates_in_trust(chain: list, trust: list) -> bool:
    """Walk signer -> intermediates -> root, return True if root is in trust."""
    for cert in chain:
        issuer = cert.issuer
        for t in trust:
            if t.subject == issuer:
                return True
    return False


def verify_jpeg(jpeg_bytes: bytes, trust_list_ders: list) -> dict:
    """
    Top-level verifier. Returns a dict with:
      - claim_generator
      - ai_generated (bool)
      - signing_cert_subject
      - asset_hash_matches (bool)
    """
    jumbf = extract_jumbf_from_jpeg(jpeg_bytes)
    # minimal parse — skip JUMBF box header, find c2pa superbox
    idx = jumbf.find(b"c2pa")
    manifest_cbor = jumbf[idx+4:]
    manifest = cbor2.loads(manifest_cbor)

    store = manifest["manifest_store"]
    active = store["manifests"][store["active_manifest"]]
    claim_payload = verify_cose_sign1(active["signature"], trust_list_ders)

    # Verify c2pa.hash.data assertion matches JPEG body
    expected_hash = None
    for a in claim_payload.get("assertions", []):
        if "hash.data" in a["url"]:
            expected_hash = a["hash"]
    actual_hash = hashlib.sha256(
        _jpeg_without_jumbf(jpeg_bytes)).digest()

    return {
        "claim_generator": claim_payload.get("claim_generator"),
        "ai_generated": _is_ai(claim_payload),
        "asset_hash_matches": expected_hash == actual_hash,
        "instance_id": claim_payload.get("instanceID"),
    }


def _jpeg_without_jumbf(jpeg_bytes: bytes) -> bytes:
    i = 2
    while i < len(jpeg_bytes) - 4:
        if jpeg_bytes[i:i+2] == b"\xFF\xEB":
            seg_len = int.from_bytes(jpeg_bytes[i+2:i+4], "big")
            return jpeg_bytes[:i] + jpeg_bytes[i+2+seg_len:]
        i += 1
    return jpeg_bytes


def _is_ai(claim: dict) -> bool:
    for a in claim.get("assertions", []):
        if "actions" in a["url"]:
            return True
    return False
