"""
bwc_clip_signing_and_dems_ingest.py

Body-worn camera → dock → Digital Evidence Management System (DEMS)
clip ingest with per-clip signing. Pattern matches Axon
evidence.com, Motorola CommandCentral Evidence, Getac Enterprise
VMS.

The BWC side in production is C/C++ on the camera SoC; the DEMS
ingest side is Python/Go/Java at scale. Shown here as Python for
readability — the signing primitives are the load-bearing part.
"""

from __future__ import annotations
import hashlib
import json
import os
import time
from dataclasses import dataclass, asdict
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509 import load_pem_x509_certificate


# ---------------------------------------------------------------
# 1. Per-clip signing record — the court-admissible artefact
# ---------------------------------------------------------------

@dataclass
class SignedClipManifest:
    device_serial: str
    officer_badge: str
    officer_login_ts: int
    clip_id: str                   # UUID
    clip_sha256_hex: str
    start_ts_utc: int
    end_ts_utc: int
    gnss_start: Optional[tuple[float, float]]
    gnss_end:   Optional[tuple[float, float]]
    firmware_build: str
    device_cert_pem: str
    signature_b64: str             # over the canonicalised manifest
                                   # excluding this field


def canonical_bytes(m: SignedClipManifest) -> bytes:
    d = asdict(m)
    d.pop("signature_b64", None)
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def bwc_sign_clip(
    clip_path: str,
    device_serial: str,
    officer_badge: str,
    officer_login_ts: int,
    gnss_start: tuple[float, float] | None,
    gnss_end:   tuple[float, float] | None,
    firmware_build: str,
    device_cert_pem: str,
    device_key: rsa.RSAPrivateKey,
) -> SignedClipManifest:
    h = hashlib.sha256()
    with open(clip_path, "rb") as fh:
        for blk in iter(lambda: fh.read(1 << 20), b""):
            h.update(blk)

    m = SignedClipManifest(
        device_serial=device_serial,
        officer_badge=officer_badge,
        officer_login_ts=officer_login_ts,
        clip_id=os.path.basename(clip_path).split(".")[0],
        clip_sha256_hex=h.hexdigest(),
        start_ts_utc=_probe_start_ts(clip_path),
        end_ts_utc=_probe_end_ts(clip_path),
        gnss_start=gnss_start,
        gnss_end=gnss_end,
        firmware_build=firmware_build,
        device_cert_pem=device_cert_pem,
        signature_b64="",
    )

    sig = device_key.sign(
        canonical_bytes(m),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    import base64
    m.signature_b64 = base64.b64encode(sig).decode()
    return m


# ---------------------------------------------------------------
# 2. Dock upload → DEMS ingest verifier
# ---------------------------------------------------------------

class DemsIngestError(Exception): pass


def dems_verify_and_ingest(
    clip_path: str,
    manifest_json: str,
    vendor_device_ca_pem: bytes,
) -> None:
    from cryptography.x509 import load_pem_x509_certificate
    import base64

    m = SignedClipManifest(**json.loads(manifest_json))

    # 1. Chain device cert to vendor-operated per-device CA. In
    #    production this is Axon's evidence.com issuing CA or
    #    Motorola CommandCentral issuing CA, itself anchored in the
    #    vendor root bundle that DEMS pins.
    device_cert = load_pem_x509_certificate(m.device_cert_pem.encode())
    vendor_ca   = load_pem_x509_certificate(vendor_device_ca_pem)
    # (full chain-building not shown — production uses a CertStore.)
    vendor_ca.public_key().verify(
        device_cert.signature,
        device_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        device_cert.signature_hash_algorithm,
    )

    # 2. Recompute clip SHA-256.
    h = hashlib.sha256()
    with open(clip_path, "rb") as fh:
        for blk in iter(lambda: fh.read(1 << 20), b""):
            h.update(blk)
    if h.hexdigest() != m.clip_sha256_hex:
        raise DemsIngestError("clip body does not match manifest hash")

    # 3. Verify device signature.
    pub = device_cert.public_key()
    pub.verify(
        base64.b64decode(m.signature_b64),
        canonical_bytes(m),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )

    # 4. Anti-replay / monotonic clip-id per device per officer-login.
    if _dems_db_has_clip(m.device_serial, m.clip_id):
        raise DemsIngestError("duplicate clip id")

    _dems_db_record(m, clip_path)
    _write_audit_entry("ingest", m)


# ---------------------------------------------------------------
# 3. CJIS-backed officer access log
#
#    Every DEMS view/download/export is written as a signed audit
#    entry. The DEMS app server holds the audit signing key (HSM-
#    backed); officer identity in the entry is the CJIS-federated
#    subject. A signed hash-chain over the audit table is the
#    accountability record.
# ---------------------------------------------------------------

class AuditChain:
    def __init__(self, app_signing_key: rsa.RSAPrivateKey):
        self._k = app_signing_key
        self._prev_hash = b"\x00" * 32

    def append(self, action: str, clip_id: str, officer_upn: str,
               ip: str, extra: dict) -> dict:
        entry = {
            "ts": int(time.time()),
            "action": action,      # VIEW | DOWNLOAD | EXPORT | REDACT
            "clip_id": clip_id,
            "officer_upn": officer_upn,
            "ip": ip,
            "extra": extra,
            "prev_hash": self._prev_hash.hex(),
        }
        body = json.dumps(entry, sort_keys=True,
                          separators=(",", ":")).encode()
        sig = self._k.sign(
            body,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
        entry["sig"] = sig.hex()
        self._prev_hash = hashlib.sha256(body + sig).digest()
        return entry


# ---------------------------------------------------------------
# 4. Redaction-chain signature
#
#    When a redactor produces a derived clip (face blur, audio
#    mute, metadata scrub), it signs a "derivation manifest" tying
#    the derived clip's SHA-256 to the original clip's SHA-256
#    plus the redaction-tool identity. This is what the defense
#    gets to verify that what they received came from the
#    evidence-in-custody.
# ---------------------------------------------------------------

@dataclass
class RedactionManifest:
    original_clip_id: str
    original_sha256_hex: str
    derived_clip_id: str
    derived_sha256_hex: str
    redaction_tool: str
    redaction_tool_version: str
    redactor_officer_upn: str
    redactor_ts: int
    signature_b64: str


def sign_redaction(original_sha256: str, derived_path: str,
                   original_clip_id: str, derived_clip_id: str,
                   redactor_officer_upn: str,
                   redaction_tool_key: rsa.RSAPrivateKey
                   ) -> RedactionManifest:
    h = hashlib.sha256()
    with open(derived_path, "rb") as fh:
        for blk in iter(lambda: fh.read(1 << 20), b""):
            h.update(blk)
    m = RedactionManifest(
        original_clip_id=original_clip_id,
        original_sha256_hex=original_sha256,
        derived_clip_id=derived_clip_id,
        derived_sha256_hex=h.hexdigest(),
        redaction_tool="Axon Redaction Studio",
        redaction_tool_version="2026.1",
        redactor_officer_upn=redactor_officer_upn,
        redactor_ts=int(time.time()),
        signature_b64="",
    )
    import base64
    d = asdict(m); d.pop("signature_b64")
    body = json.dumps(d, sort_keys=True, separators=(",", ":")).encode()
    sig = redaction_tool_key.sign(
        body,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    m.signature_b64 = base64.b64encode(sig).decode()
    return m


# Probe helpers (stubs) ---------------------------------------------
def _probe_start_ts(p: str) -> int: return int(os.path.getctime(p))
def _probe_end_ts(p: str)   -> int: return int(os.path.getmtime(p))
def _dems_db_has_clip(ds: str, cid: str) -> bool: return False
def _dems_db_record(m, p): pass
def _write_audit_entry(a, m): pass


# ---- Breakage ----------------------------------------------------
#
#   BWC device-issuing CA factored (Axon, Motorola, Getac):
#     - Attacker mints device certs; produces signed-video
#       forgeries of events that never happened, or of people
#       present at locations they were not. Defense motions to
#       exclude succeed routinely; prosecutors lose the primary
#       digital-evidence pillar of modern policing.
#
#   Vendor firmware root factored:
#     - Fleet-wide signed firmware that silently disables
#       per-clip signing. Every subsequent BWC video loses
#       F.R.E. 902(13)-(14) self-authentication. Every case
#       relying on post-compromise BWC needs traditional
#       foundation testimony.
#
#   DEMS app-audit signing key factored:
#     - "Who viewed this clip" audit trail becomes forgeable.
#       Misuse-of-police-information investigations lose their
#       accountability anchor.
#
#   Redaction-tool signing root factored:
#     - Derivation chain from original → disclosed clip is no
#       longer cryptographic. Defense cannot verify the
#       disclosure matches the in-custody original.
