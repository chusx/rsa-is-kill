"""
transfusion_and_recall_chain.py

Blood-bank middleware: ISBT-128 DIN receipt, crossmatch-result
signing, transfusion-administration event capture, and recall
propagation. Pattern matches Haemonetics SafeTrace Tx, SCC Soft
SoftBank, WellSky HCLL Transfusion. Python here for readability;
vendor platforms are .NET/Java/VB6-era mixes.
"""
from __future__ import annotations
import hashlib
import json
import time
from dataclasses import dataclass, asdict
from typing import Iterable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


# ---------------------------------------------------------------
# 1. Incoming DIN (Donation Identification Number) + product label
# ---------------------------------------------------------------

@dataclass
class IsbtProductLabel:
    din: str                       # e.g. "W036720078412"
    product_code: str              # ISBT 128 product code (E0336 etc)
    abo_rhd: str                   # "A POS"
    expiry_utc: int
    collection_facility_id: str    # ICCBBA-assigned FIN
    donor_hash: str                # one-way hash, never the NDI
    sig: bytes                     # blood-service signature


def verify_product_label(lbl: IsbtProductLabel,
                         facility_pubkeys: dict[str, rsa.RSAPublicKey],
                         iccbba_root_pub: rsa.RSAPublicKey) -> None:
    pk = facility_pubkeys.get(lbl.collection_facility_id)
    if pk is None:
        raise ValueError(f"unknown FIN {lbl.collection_facility_id}")
    body = canonical(asdict(lbl), drop="sig")
    pk.verify(
        lbl.sig, body,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    # facility_pubkeys is itself a trust-on-signature list issued by
    # ICCBBA and periodically re-published; a compromise of the
    # ICCBBA root factored by an adversary would produce valid-
    # looking facility keys for units that never existed.


# ---------------------------------------------------------------
# 2. Crossmatch / type-and-screen result signing
# ---------------------------------------------------------------

@dataclass
class CrossmatchResult:
    order_id: str
    patient_mrn_hash: str
    unit_din: str
    patient_abo_rhd: str
    unit_abo_rhd: str
    crossmatch_status: str         # "COMPATIBLE" | "INCOMPATIBLE"
    tech_initials: str
    verified_by_initials: str
    laboratory_id: str
    performed_ts: int
    sig: bytes


def sign_crossmatch(res: CrossmatchResult,
                    lab_signing_key: rsa.RSAPrivateKey) -> CrossmatchResult:
    body = canonical(asdict(res), drop="sig")
    sig = lab_signing_key.sign(
        body,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    return CrossmatchResult(**{**asdict(res), "sig": sig})


# ---------------------------------------------------------------
# 3. Transfusion administration — the at-bedside act
#
# AABB Standards / 21 CFR 606.160 require each transfusion to be
# recorded with: who administered, when, which unit, which patient,
# vital signs at start/end, any adverse reaction. Signed into the
# EHR's blood-bank module.
# ---------------------------------------------------------------

@dataclass
class TransfusionRecord:
    visit_id: str
    patient_mrn_hash: str
    unit_din: str
    ordering_provider_npi: str
    administering_rn_id: str
    verifier_rn_id: str
    start_ts: int
    end_ts: int
    volume_ml: int
    reaction_observed: bool
    reaction_text: str
    unit_return_to_bb_reason: str  # empty if completed
    sig: bytes


def sign_transfusion_record(r: TransfusionRecord,
                            hospital_bb_key: rsa.RSAPrivateKey
                            ) -> TransfusionRecord:
    body = canonical(asdict(r), drop="sig")
    sig = hospital_bb_key.sign(
        body,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    return TransfusionRecord(**{**asdict(r), "sig": sig})


# ---------------------------------------------------------------
# 4. Recall propagation — look-back notification
# ---------------------------------------------------------------

@dataclass
class LookbackNotice:
    issuing_service_id: str
    affected_dins: list[str]
    reason_code: str               # e.g. "POST-DONATION-INFORM-HCV"
    effective_ts: int
    instructions_text: str
    sig: bytes


def verify_lookback(notice: LookbackNotice,
                    service_pubkeys: dict[str, rsa.RSAPublicKey]
                    ) -> None:
    pk = service_pubkeys[notice.issuing_service_id]
    body = canonical(asdict(notice), drop="sig")
    pk.verify(
        notice.sig, body,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )


def propagate_lookback(notice: LookbackNotice) -> list[str]:
    """Given an upstream-signed recall, identify downstream
    transfusion recipients and return the list of patient MRN
    hashes that must be notified + the clinician-to-notify NPI.

    Chain integrity collapses if any of the verify steps above
    accept a forged notice (denial of recall: attacker sends
    "cancel" after a real recall) or a forged-positive notice
    (denial of supply during emergencies — e.g. mass-casualty).
    """
    affected_patients: list[str] = []
    for din in notice.affected_dins:
        for tx in db_find_transfusions_of(din):
            affected_patients.append(tx.patient_mrn_hash)
    return affected_patients


# ---------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------

def canonical(d: dict, drop: str) -> bytes:
    d2 = {k: v for k, v in d.items() if k != drop}
    return json.dumps(d2, sort_keys=True, separators=(",", ":"),
                      default=str).encode()


def db_find_transfusions_of(din: str) -> Iterable[TransfusionRecord]:
    return []


# ---- Breakage ------------------------------------------------------
#
#   ICCBBA FIN / DIN-signing root factored:
#     - Counterfeit units issued with valid labels enter clinical
#       supply. Untested plasma / whole blood — HIV/HCV/HBV/Chagas
#       risk at patient scale.
#
#   Crossmatch laboratory signing key factored:
#     - Forged "compatible" results — wrong-ABO transfusion
#       reactions are historically a fatality source.
#
#   Recall / look-back signing root factored:
#     - False-cancel of a real recall; or false-positive recall
#       denying supply during a mass-casualty event.
#
#   UNOS / Eurotransplant allocation root factored:
#     - Organ offers mis-routed, acceptance chains forged —
#       life-saving offers reach wrong recipients; policy audit
#       trail becomes meaningless.
