"""
c2pa_manifest_sign.py

C2PA 2.x Content Credentials — build, sign, and embed a provenance manifest
for AI-generated media.

Spec refs:
  - C2PA Technical Specification 2.1 (2024)
  - RFC 8152 COSE
  - ISO 19566-5 JUMBF
  - IETF draft-rosenthol-jpeg-app11

The signing path used by OpenAI DALL-E, Adobe Firefly, and MSFT Designer
is essentially:

    claim (CBOR) --> signed_claim (COSE Sign1) --> embedded JUMBF --> JPEG/MP4

All three vendors use HSM-backed RSA keys for the Sign1 signature today.
"""

import cbor2
import hashlib
import json
from datetime import datetime, timezone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509 import load_pem_x509_certificate


CLAIM_GENERATOR = "OpenAI Image Generator/1.0 (gpt-image-1)"


def build_claim(asset_hash: bytes,
                is_ai_generated: bool,
                ingredients: list,
                generator_info: str = CLAIM_GENERATOR) -> dict:
    """
    Build a C2PA claim dict. `asset_hash` is SHA-256 of the JPEG bytes
    excluding the manifest region. `ingredients` names parent assets.
    """
    assertions = [
        {
            "label": "c2pa.hash.data",
            "data": {
                "exclusions": [],
                "alg": "sha256",
                "hash": asset_hash,
                "name": "jumbf manifest",
            },
        },
        {
            "label": "stds.schema-org.CreativeWork",
            "data": {
                "@context": "https://schema.org/",
                "@type": "CreativeWork",
                "author": [{"@type": "Organization", "name": "OpenAI"}],
            },
        },
    ]

    if is_ai_generated:
        assertions.append({
            "label": "c2pa.actions.v2",
            "data": {
                "actions": [{
                    "action": "c2pa.created",
                    "when": datetime.now(timezone.utc).isoformat(),
                    "digitalSourceType":
                        "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia",
                    "softwareAgent": {"name": generator_info},
                }],
            },
        })

    for ing in ingredients:
        assertions.append({
            "label": "c2pa.ingredient.v3",
            "data": ing,
        })

    return {
        "claim_generator": generator_info,
        "claim_generator_info": [{"name": generator_info}],
        "signature": "self#jumbf=c2pa.signature",
        "assertions": [
            {"url": f"self#jumbf=c2pa.assertions/{a['label']}",
             "hash": hashlib.sha256(cbor2.dumps(a["data"])).digest(),
             "alg": "sha256"}
            for a in assertions
        ],
        "alg": "sha256",
        "instanceID": f"xmp:iid:{hashlib.sha256(asset_hash).hexdigest()[:32]}",
    }


def cose_sign1_rsa(payload: bytes,
                   signing_key: rsa.RSAPrivateKey,
                   signing_cert_der: bytes,
                   cert_chain_der: list) -> bytes:
    """
    Produce a COSE Sign1 over `payload` using RSA-PSS (PS256) — the
    predominant algorithm used by production C2PA signers today.

    COSE Sign1 structure (RFC 8152 §4.2):
        Sig_structure = [context, body_protected, external_aad, payload]
        COSE_Sign1 = [protected, unprotected, payload, signature]
    """
    # protected header: alg = PS256 (-37), x5chain = cert chain DER
    protected = cbor2.dumps({
        1: -37,                                  # alg: PS256
        33: [signing_cert_der] + cert_chain_der, # x5chain
    })
    unprotected = {}

    # Sig_structure per RFC 8152
    sig_structure = cbor2.dumps([
        "Signature1",
        protected,
        b"",         # external_aad
        payload,
    ])

    signature = signing_key.sign(
        sig_structure,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    cose_sign1 = cbor2.dumps(cbor2.CBORTag(18, [
        protected,
        unprotected,
        payload,
        signature,
    ]))
    return cose_sign1


def build_jumbf_box(claim_cbor: bytes, cose_sig: bytes) -> bytes:
    """
    Wrap the claim + signature in a JUMBF superbox targeting C2PA
    (ISO 19566-5). Real implementations use c2pa-rs or c2patool; the
    layout here is abbreviated.
    """
    # JUMBF type boxes (4CC) for C2PA
    c2pa_box = b"jumd" + b"c2pa" + cbor2.dumps({
        "manifest_store": {
            "active_manifest": "urn:uuid:openai-image-1",
            "manifests": {
                "urn:uuid:openai-image-1": {
                    "claim": claim_cbor,
                    "signature": cose_sig,
                },
            },
        },
    })

    box_size = len(c2pa_box) + 8
    return box_size.to_bytes(4, "big") + b"jumb" + c2pa_box


def embed_jumbf_in_jpeg(jpeg_bytes: bytes, jumbf_box: bytes) -> bytes:
    """
    Embed a JUMBF box into a JPEG via APP11 marker per ISO/IEC 19566-5
    and JPEG Systems. Returns new JPEG bytes.
    """
    app11 = b"\xFF\xEB" + (len(jumbf_box) + 2).to_bytes(2, "big") + jumbf_box
    # Insert after SOI (0xFFD8)
    assert jpeg_bytes[:2] == b"\xFF\xD8"
    return jpeg_bytes[:2] + app11 + jpeg_bytes[2:]


def sign_and_embed(jpeg_bytes: bytes,
                   is_ai_generated: bool,
                   signing_key: rsa.RSAPrivateKey,
                   signing_cert_pem: bytes,
                   cert_chain_pem: list,
                   ingredients: list = None) -> bytes:
    """
    End-to-end: take raw JPEG bytes, produce a C2PA-signed JPEG.
    This is the flow invoked server-side for every DALL-E/Firefly
    image before it's returned to the user.
    """
    asset_hash = hashlib.sha256(jpeg_bytes).digest()
    claim = build_claim(asset_hash, is_ai_generated, ingredients or [])
    claim_cbor = cbor2.dumps(claim)

    signing_cert_der = load_pem_x509_certificate(signing_cert_pem).public_bytes(
        serialization.Encoding.DER)
    chain_der = [load_pem_x509_certificate(c).public_bytes(serialization.Encoding.DER)
                 for c in cert_chain_pem]

    cose_sig = cose_sign1_rsa(claim_cbor, signing_key, signing_cert_der, chain_der)
    jumbf = build_jumbf_box(claim_cbor, cose_sig)
    return embed_jumbf_in_jpeg(jpeg_bytes, jumbf)
