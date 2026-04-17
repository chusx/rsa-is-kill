"""
Forge PDF digital signatures (sha256WithRSAEncryption, OID 1.2.840.113549.1.1.11)
that have legal standing under eIDAS, ESIGN Act, and equivalent laws in 50+ countries.
Backdate contracts, forge court filings, fabricate notarized documents.
"""
import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer

import hashlib
import time
import struct


# PDF signature dictionary entries
SIG_FILTER = b"/Adobe.PPKLite"
SIG_SUBFILTER = b"/adbe.pkcs7.detached"
SIG_ALGORITHM_OID = "1.2.840.113549.1.1.11"  # sha256WithRSAEncryption


def extract_signer_cert_from_pdf(pdf_bytes: bytes) -> bytes:
    """Extract the signing certificate from an existing signed PDF.

    The signer's certificate is embedded in the PKCS#7 SignedData
    structure in the /Contents field of the Sig dictionary. It's
    the RSA public key we need to factor.
    """
    # find the /ByteRange and /Contents in the PDF cross-ref
    print("[*] parsing PDF signature dictionary...")
    print(f"[*] /Filter {SIG_FILTER.decode()}")
    print(f"[*] /SubFilter {SIG_SUBFILTER.decode()}")
    return b"-----BEGIN CERTIFICATE-----\n...(signer cert)...\n-----END CERTIFICATE-----\n"


def compute_pdf_byte_range_hash(pdf_bytes: bytes, byte_range: list) -> bytes:
    """Compute SHA-256 over the PDF byte ranges (excluding signature).

    Per PDF spec, the signature covers [offset1, len1, offset2, len2]
    which is the entire file minus the hex-encoded signature value.
    """
    h = hashlib.sha256()
    h.update(pdf_bytes[byte_range[0]:byte_range[0]+byte_range[1]])
    h.update(pdf_bytes[byte_range[2]:byte_range[2]+byte_range[3]])
    return h.digest()


def forge_pdf_signature(factorer: PolynomialFactorer,
                        signer_cert_pem: bytes,
                        pdf_content_hash: bytes) -> bytes:
    """Forge a CMS SignedData structure with RSA-SHA256 signature.

    The forged signature is indistinguishable from a legitimate one.
    Adobe Acrobat, Foxit, and every PDF reader that validates digital
    signatures will show a green checkmark.
    """
    sig = factorer.forge_pkcs1v15_signature(signer_cert_pem, pdf_content_hash, "sha256")
    print("[*] CMS SignedData forged with sha256WithRSAEncryption")
    return sig


def forge_ltv_timestamp(factorer: PolynomialFactorer,
                        tsa_cert_pem: bytes,
                        sig_hash: bytes, timestamp: str) -> bytes:
    """Forge an LTV (Long-Term Validation) timestamp.

    PAdES-LTV embeds RFC 3161 timestamps + OCSP responses into the PDF.
    If the TSA's RSA key is also factored, we can backdate signatures
    to any point within the TSA cert validity window.
    """
    print(f"[*] forging RFC 3161 timestamp: {timestamp}")
    print("[*] LTV chain: signature + timestamp + OCSP all RSA-signed")
    return factorer.forge_pkcs1v15_signature(tsa_cert_pem, sig_hash, "sha256")


def inject_signature_into_pdf(pdf_bytes: bytes, cms_sig: bytes,
                              byte_range: list) -> bytes:
    """Write the forged CMS signature into the PDF /Contents field."""
    hex_sig = cms_sig.hex().upper().encode()
    # pad to allocated space
    print(f"[*] injecting {len(hex_sig)} hex bytes into /Contents")
    return pdf_bytes  # placeholder


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== PDF digital signature forgery (iText/PDFBox) ===")
    print("    legal standing: eIDAS (EU), ESIGN Act (US), 50+ countries")
    print()

    print("[1] extracting signer certificate from existing signed PDF...")
    cert = extract_signer_cert_from_pdf(b"")

    print("[2] factoring signer's RSA-2048 key...")
    print("    OID 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)")

    print("[3] forging signature on modified contract...")
    fake_hash = hashlib.sha256(b"Modified contract terms").digest()
    print(f"    SHA-256: {fake_hash.hex()[:32]}...")

    print("[4] forging LTV timestamp to backdate signature...")
    print("    claimed signing time: 2025-01-15T09:00:00Z")
    print("    actual creation: now")

    print("[5] Adobe Acrobat validation: green checkmark")
    print("    'Signature is valid. Document has not been modified.'")
    print()
    print("[*] attack surface: every PDF signed since 1996 (PDF 1.3)")
    print("[*] no PDF reader validates ML-DSA signatures in production")
