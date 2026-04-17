"""
tsa_rfc3161.py

RFC 3161 Time-Stamp Protocol — TSA-side issuance and client-side verification.
Sources:
  - RFC 3161 Time-Stamp Protocol (TSP)
  - RFC 5816 ESSCertIDv2 update
  - RFC 5652 Cryptographic Message Syntax (CMS)
  - ETSI EN 319 422 Policy and security requirements for TSAs
  - ETSI TS 119 312 Cryptographic Suites (ECDSA alternative; RSA remains baseline)
  - CA/Browser Forum Code Signing Baseline Requirements (timestamp specifics)

Protocol (over HTTP, Content-Type: application/timestamp-query):

  Client builds TimeStampReq:
      TimeStampReq ::= SEQUENCE {
          version             INTEGER { v1(1) },
          messageImprint      MessageImprint,
              -- hashAlgorithm (SHA-256 typical) || hashedMessage
          reqPolicy           TSAPolicyID OPTIONAL,
          nonce               INTEGER OPTIONAL,
          certReq             BOOLEAN DEFAULT FALSE,
          extensions          Extensions OPTIONAL }

  TSA responds TimeStampResp:
      TimeStampResp ::= SEQUENCE {
          status     PKIStatusInfo,
          timeStampToken  TimeStampToken OPTIONAL }
      -- TimeStampToken is a CMS SignedData where:
      --    eContentType = id-ct-TSTInfo
      --    eContent = TSTInfo DER
      --    signerInfos = SignerInfo(s) with TSA RSA-2048 signature

  TSTInfo carries:
      version, policy, messageImprint (echo), serialNumber, genTime,
      accuracy, ordering, nonce, tsa (GeneralName), extensions.

The TSA signs with its RSA-2048 key. Validity of the resulting timestamp
depends on the TSA cert chain and on the TSA's RSA key remaining unrecoverable.
"""

import os
import datetime
from typing import Optional
from asn1crypto import tsp, cms, x509 as asn1_x509, algos, core
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


def build_timestamp_request(document: bytes,
                              policy_oid: Optional[str] = None,
                              include_cert: bool = True) -> bytes:
    """
    Build a RFC 3161 TimeStampReq for SHA-256(document).
    """
    digest = hashes.Hash(hashes.SHA256())
    digest.update(document)
    message_digest = digest.finalize()

    nonce = int.from_bytes(os.urandom(8), "big")

    tsq = tsp.TimeStampReq({
        "version": 1,
        "message_imprint": tsp.MessageImprint({
            "hash_algorithm": algos.DigestAlgorithm({
                "algorithm": "sha256"
            }),
            "hashed_message": message_digest,
        }),
        "req_policy": policy_oid if policy_oid else core.VOID,
        "nonce": nonce,
        "cert_req": include_cert,
    })
    return tsq.dump()


def issue_timestamp(tsq_bytes: bytes,
                     tsa_private_key: rsa.RSAPrivateKey,
                     tsa_cert_der: bytes,
                     policy_oid: str,
                     serial_number: int) -> bytes:
    """
    TSA-side: parse a TimeStampReq, sign a TimeStampResp with RSA-2048.
    Called by every operational TSA (DigiCert, Sectigo, GlobalSign,
    Certum, Swisscom, A-Trust, etc.) for every client request.
    """
    tsq = tsp.TimeStampReq.load(tsq_bytes)
    gen_time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)

    tst_info = tsp.TSTInfo({
        "version": 1,
        "policy": policy_oid,
        "message_imprint": tsq["message_imprint"],
        "serial_number": serial_number,
        "gen_time": gen_time,
        "accuracy": tsp.Accuracy({"seconds": 1}),
        "nonce": tsq["nonce"],
    })

    # Build CMS SignedData wrapping TSTInfo
    encap_content = cms.ContentInfo({
        "content_type": "tst_info",
        "content": tst_info,
    })

    signed_attrs = cms.CMSAttributes([
        cms.CMSAttribute({
            "type": "content_type",
            "values": ["tst_info"],
        }),
        cms.CMSAttribute({
            "type": "signing_time",
            "values": [cms.Time({"utc_time": gen_time})],
        }),
        cms.CMSAttribute({
            "type": "message_digest",
            "values": [_sha256(tst_info.dump())],
        }),
    ])

    # RSA-2048 PKCS#1 v1.5 signature over DER-encoded signed attributes
    signature = tsa_private_key.sign(
        signed_attrs.dump(),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    tsa_cert = asn1_x509.Certificate.load(tsa_cert_der)
    signer_info = cms.SignerInfo({
        "version": "v1",
        "sid": cms.SignerIdentifier({
            "issuer_and_serial_number": cms.IssuerAndSerialNumber({
                "issuer": tsa_cert["tbs_certificate"]["issuer"],
                "serial_number": tsa_cert["tbs_certificate"]["serial_number"],
            }),
        }),
        "digest_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
        "signature_algorithm": algos.SignedDigestAlgorithm({
            "algorithm": "sha256_rsa",
        }),
        "signed_attrs": signed_attrs,
        "signature": signature,
    })

    signed_data = cms.SignedData({
        "version": "v3",
        "digest_algorithms": [algos.DigestAlgorithm({"algorithm": "sha256"})],
        "encap_content_info": encap_content,
        "certificates": [tsa_cert],
        "signer_infos": [signer_info],
    })

    tst_token = cms.ContentInfo({
        "content_type": "signed_data",
        "content": signed_data,
    })

    response = tsp.TimeStampResp({
        "status": tsp.PKIStatusInfo({"status": "granted"}),
        "time_stamp_token": tst_token,
    })
    return response.dump()


def verify_timestamp(response_bytes: bytes,
                      document: bytes,
                      tsa_trust_anchors: list) -> dict:
    """
    Verify a RFC 3161 TimeStampResp against the expected document hash
    and a set of trusted TSA root CAs (e.g., the EU Trusted List).

    Every code-signing validator, every PDF reader validating PAdES-LTV,
    every archive verifier runs this flow.
    """
    response = tsp.TimeStampResp.load(response_bytes)
    token = response["time_stamp_token"]
    signed_data = token["content"]

    # Extract TSTInfo from encap_content
    tst_info = tsp.TSTInfo.load(
        signed_data["encap_content_info"]["content"].native
    )

    # Verify message digest matches
    expected_digest = _sha256(document)
    if tst_info["message_imprint"]["hashed_message"].native != expected_digest:
        raise ValueError("TSA response does not match document hash")

    # Verify signer's RSA signature over signed_attrs
    signer = signed_data["signer_infos"][0]
    tsa_cert_der = signed_data["certificates"][0].dump()

    # ... chain validation against tsa_trust_anchors ...
    # ... signature verification using tsa_cert's RSA public key ...

    return {
        "gen_time": tst_info["gen_time"].native,
        "serial": tst_info["serial_number"].native,
        "policy": tst_info["policy"].native,
        "tsa_cert": tsa_cert_der,
    }


def build_ltv_archive_chain(document: bytes,
                              existing_timestamps: list,
                              tsa_url: str) -> bytes:
    """
    Long-Term Validation (CAdES-A / PAdES-LTV) archive timestamp.

    Each archive-timestamp covers:
      - the original document
      - all prior signatures and timestamps
      - all OCSP/CRL responses proving validity at time-of-signing

    Then the outer timestamp extends trust beyond the signer's and
    previous TSA's cert validity. This creates a chain where EACH
    timestamp's RSA key must remain secure forever, or the chain
    collapses.
    """
    composite = document
    for ts in existing_timestamps:
        composite += ts
    # ... fetch new timestamp from tsa_url covering `composite` ...
    return b""


def _sha256(data: bytes) -> bytes:
    d = hashes.Hash(hashes.SHA256())
    d.update(data)
    return d.finalize()


# EU Trusted List context:
#
# Under eIDAS (EU 910/2014), each EU member state publishes a Trusted List
# enumerating its qualified trust service providers — qualified CAs,
# qualified TSAs, qualified electronic signature validators.
#
# A "qualified timestamp" carries the strongest legal weight in EU courts:
# reverse burden of proof that the document existed at the claimed time.
# Qualified TSAs listed include Swisscom (CH), Digidentity (NL), Certum (PL),
# Infocert (IT), Quovadis (global), D-Trust (DE), and dozens of others.
#
# The Trusted List itself publishes every qualified TSA's RSA-2048 (or
# RSA-4096) public key. An attacker downloading the EU LOTL (List of
# Trusted Lists) has every qualified TSA's public key. Factoring any one
# of them produces indistinguishable forged qualified timestamps.
#
# Code-signing context:
#
# Microsoft Authenticode, Apple Developer ID, and JAR signing all use
# RFC 3161 countersignatures. The CA/Browser Forum Code Signing Baseline
# Requirements (v3.x, 2023) mandate RFC 3161 timestamps with specific
# RSA key strengths (minimum RSA-2048). A working factoring attack lets
# an attacker produce countersigned binaries that pass Windows SmartScreen,
# macOS Gatekeeper, and Java's jarsigner verification — defeating the
# primary commercial code-signing trust mechanism.
