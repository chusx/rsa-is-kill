"""
finish_line_and_ratification.py

Finish-line timing aggregator (pattern: MYLAPS BibTag Pro +
RR-Timing-Box backend) — ingests decoder transponder reads, signs
the race's finish manifest, hands off to federation ratification
endpoint + WADA ADAMS feed.
"""
from __future__ import annotations
import hashlib
import json
import time
from dataclasses import dataclass, asdict, field

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


# ---------------------------------------------------------------
# 1. Decoder-level signed transponder reads
# ---------------------------------------------------------------

@dataclass
class TranspRead:
    decoder_serial: str
    event_id: str                 # e.g. "boston-2026"
    transponder_id: str
    bib: str
    cross_ts_ms: int              # UTC ms, decoder-disciplined GPS clock
    split_code: str               # "F", "5K", "HALF", "35K", "KOM-17"
    decoder_sig: bytes            # RSA-2048 PSS, decoder HSM


def verify_read(r: TranspRead,
                decoder_pubkeys: dict[str, rsa.RSAPublicKey]) -> None:
    pk = decoder_pubkeys[r.decoder_serial]
    body = canonical(asdict(r), drop="decoder_sig")
    pk.verify(
        r.decoder_sig, body,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )


# ---------------------------------------------------------------
# 2. Race finish manifest — timing-provider signed
# ---------------------------------------------------------------

@dataclass
class FinishEntry:
    bib: str
    transponder_id: str
    chip_ms: int                  # net time
    gun_ms: int                   # gross time
    overall_place: int
    gender_place: int
    age_group_place: int


@dataclass
class FinishManifest:
    event_id: str
    event_class: str              # "MARATHON-WA", "UCI-WT-STAGE", "IRONMAN"
    start_gun_ts_ms: int
    first_crossing_ts_ms: int
    entries: list[FinishEntry]
    course_length_m: int
    course_cert_id: str           # AIMS / USATF course-measurement cert
    provider: str                 # "MYLAPS", "RACERESULT", ...
    decoder_serials: list[str]
    provider_sig: bytes = b""


def sign_manifest(m: FinishManifest,
                  provider_key: rsa.RSAPrivateKey) -> FinishManifest:
    body = canonical(asdict(m), drop="provider_sig")
    sig = provider_key.sign(
        body,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    return FinishManifest(**{**asdict(m), "provider_sig": sig})


# ---------------------------------------------------------------
# 3. Federation record-ratification co-signature
# ---------------------------------------------------------------

@dataclass
class RecordRatification:
    federation: str               # "WA", "UCI", "FIS", "ISU"
    record_class: str             # "WORLD", "CONTINENTAL", "NATIONAL"
    discipline: str               # "MARATHON-OPEN-M"
    athlete_id: str
    event_id: str
    bib: str
    ratified_time_ms: int
    course_cert_id: str
    timing_provider_ref: str
    provider_manifest_hash: str   # sha256 of signed manifest
    sig: bytes = b""


def ratify(rr: RecordRatification,
           federation_key: rsa.RSAPrivateKey) -> RecordRatification:
    body = canonical(asdict(rr), drop="sig")
    sig = federation_key.sign(
        body,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    return RecordRatification(**{**asdict(rr), "sig": sig})


# ---------------------------------------------------------------
# 4. WADA ADAMS test-pool feed
# ---------------------------------------------------------------

@dataclass
class AdamsTestPool:
    event_id: str
    generated_ts: int
    top_n_by_discipline: dict[str, list[str]]   # discipline → list[athlete_id]
    random_selected: list[str]
    athletes_requiring_test: list[str]
    manifest_hash: str            # the finish manifest being drawn from
    provider_sig: bytes = b""


def sign_adams_pool(p: AdamsTestPool,
                    provider_key: rsa.RSAPrivateKey) -> AdamsTestPool:
    body = canonical(asdict(p), drop="provider_sig")
    sig = provider_key.sign(
        body,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    return AdamsTestPool(**{**asdict(p), "provider_sig": sig})


# ---------------------------------------------------------------
# 5. Transponder-provenance (rental bibs in mass events)
# ---------------------------------------------------------------

@dataclass
class TransponderIssue:
    event_id: str
    transponder_id: str
    issued_to_athlete_id: str
    issued_ts: int
    kiosk_serial: str
    sig: bytes = b""


def verify_transponder_issue(ti: TransponderIssue,
                             provider_pub: rsa.RSAPublicKey) -> None:
    body = canonical(asdict(ti), drop="sig")
    provider_pub.verify(
        ti.sig, body,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )


# ---------------------------------------------------------------

def canonical(d: dict, drop: str) -> bytes:
    d2 = {k: v for k, v in d.items() if k != drop}
    return json.dumps(d2, sort_keys=True, separators=(",", ":"),
                      default=str).encode()


# ---- Breakage ------------------------------------------------------
#
#   Timing-provider signing key factored:
#     - Forged finish manifests. Abbott WMM + UCI prize-money
#       payouts against fabricated times; record ratifications
#       retrospectively invalidated.
#
#   Decoder per-unit HSM key factored:
#     - Individual transponder-read forgeries; bib-swapping
#       attacks go undetected in the chip-time record.
#
#   Federation ratification key factored:
#     - Record books corruptible; sponsor-bonus clauses default
#       to manual arbitration; sport's record-integrity chain
#       collapses.
#
#   WADA ADAMS pool signing factored:
#     - Dopers avoid post-race testing via forged attribution
#       of "not selected" status. Anti-doping chain undermined
#       at a systemic level.
