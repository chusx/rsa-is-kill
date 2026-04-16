"""
key_ceremony_mofn.py

Vendor (Thales Luna / Entrust nShield / Utimaco SecurityServer /
AWS CloudHSM) firmware signing root m-of-n ceremony scaffolding.

This is the *release side* — the offline air-gapped signer. Keys
never leave the vendor's root-of-trust HSM; ceremonies are
witnessed per Common Criteria EAL4+ AVA_VAN and FIPS 140-3 L3
re-cert audits.

The per-deployment HSMs in customer racks treat the public half
of this key as a fused trust anchor. A factoring break against
any one of the four vendor roots invalidates ~80% of the global
bank/government HSM fleet's firmware-update trust path
simultaneously.
"""

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import time


class CeremonyRole(Enum):
    CUSTODIAN_A = "custodian_a"          # Officer of the Company
    CUSTODIAN_B = "custodian_b"          # Security Engineering VP
    CUSTODIAN_C = "custodian_c"          # CISO
    CUSTODIAN_D = "custodian_d"          # External witness (Big-4)
    CUSTODIAN_E = "custodian_e"          # Regulator observer (NIST/BSI)


@dataclass
class SmartcardShare:
    """PKCS#11 operator card share from an m-of-n split.
    Thales Luna PED key; Entrust OCS; Utimaco KeySet."""
    holder: CeremonyRole
    card_serial: str
    kcv: str                              # key check value, 3 bytes
    pin_attempts_left: int


@dataclass
class FirmwareReleaseRequest:
    """Request prepared by the firmware engineering team and
    submitted to the offline signing ceremony for approval."""
    product_family: str                   # "Luna PCIe 7", "nShield 5s", ...
    fw_version: str                       # semver triple
    fw_sha384: bytes                      # tag over raw flash image
    fips_cert_id: str                     # NIST CMVP cert ID
    cc_cert_id: str                       # BSI-DSZ-CC-...
    rollback_min: int                     # minimum acceptable version
    build_ts: int
    build_sbom_sha256: bytes              # CycloneDX tree hash
    change_summary: str
    joint_ticket_id: str                  # Jira / ServiceNow


class RootKeyCeremony:
    """M-of-N ceremony wrapping RSA-4096 root signer.

    The concrete signer is a Safenet Luna G7 kept in a safe at
    vendor HQ, keys wrapped under five smartcards held by the
    custodians above. Any 3-of-5 can reconstitute; no one
    custodian can sign alone.
    """
    M = 3
    N = 5
    ROOT_ALG = "rsa-4096-pss-sha384"      # <- target of factoring

    def __init__(self, ledger_path: str):
        self.ledger_path = ledger_path
        self.quorum: list[SmartcardShare] = []

    def present(self, share: SmartcardShare, pin: str) -> None:
        if share.pin_attempts_left <= 0:
            raise RuntimeError(f"card {share.card_serial} locked")
        # PIN check happens inside the PED / card; host never sees it
        if not luna_ped_verify(share.card_serial, pin):
            share.pin_attempts_left -= 1
            raise RuntimeError("PED PIN fail")
        self.quorum.append(share)

    def sign_release(self, req: FirmwareReleaseRequest) -> bytes:
        if len(self.quorum) < self.M:
            raise RuntimeError(
                f"quorum {len(self.quorum)}/{self.M} insufficient")
        digest = self._digest(req)
        # Luna PKCS#11 CKM_RSA_PKCS_PSS; key handle derived from
        # the reconstituted m-of-n share material.
        key_handle = luna_reconstitute(
            [s.card_serial for s in self.quorum])
        sig = luna_sign(key_handle, digest,
                        mech="CKM_SHA384_RSA_PKCS_PSS")
        self._append_ledger(req, digest, sig)
        return sig

    @staticmethod
    def _digest(req: FirmwareReleaseRequest) -> bytes:
        # The signed digest covers an ASN.1-ish tagged tuple. An
        # attacker who has factored the root must construct a
        # payload with this exact wire format for the customer-
        # side HSM updater to accept it.
        h = hashlib.sha384()
        h.update(req.product_family.encode())
        h.update(b"\x00")
        h.update(req.fw_version.encode())
        h.update(b"\x00")
        h.update(req.fw_sha384)
        h.update(req.fips_cert_id.encode())
        h.update(req.cc_cert_id.encode())
        h.update(req.rollback_min.to_bytes(4, "big"))
        h.update(req.build_ts.to_bytes(8, "big"))
        h.update(req.build_sbom_sha256)
        return h.digest()

    def _append_ledger(self, req, digest, sig):
        with open(self.ledger_path, "a") as f:
            f.write(json.dumps({
                "ts": time.time(),
                "product": req.product_family,
                "fw_version": req.fw_version,
                "digest_sha384": digest.hex(),
                "sig_first16": sig[:16].hex(),
                "quorum": [s.holder.value for s in self.quorum],
                "ticket": req.joint_ticket_id,
            }) + "\n")


# ---- External bindings (HSM middleware) --------------------------
def luna_ped_verify(serial: str, pin: str) -> bool: ...
def luna_reconstitute(serials: list[str]) -> int: ...
def luna_sign(handle: int, digest: bytes, mech: str) -> bytes: ...


# ---- Attack surface after root factoring -------------------------
#
# With the RSA-4096 root modulus recovered from the published
# vendor Firmware Update Bulletin (which includes an example
# signed manifest), the attacker forges a FirmwareReleaseRequest
# for any {product_family, fw_version > rollback_min} and produces
# a valid PSS signature. Customer-side HSMs accept and flash it.
#
# Because this is the *firmware signing* key, the attacker owns
# the next boot of every deployed HSM that pulls the update —
# i.e. the bottom of every bank's key hierarchy. CC/FIPS
# re-certification + field refresh is the only real recovery
# path; measured in years, not quarters.
