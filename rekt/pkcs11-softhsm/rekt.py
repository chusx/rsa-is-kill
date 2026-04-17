"""
Bypass the HSM trust boundary entirely by factoring RSA keys stored behind
PKCS#11 interfaces. The private key never leaves the HSM — but the factoring
algorithm derives it from the public key, which PKCS#11 exposes freely via
C_GetAttributeValue(CKA_MODULUS).
"""
import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer

# PKCS#11 mechanism constants (v3.1) — all RSA, no PQC
CKM_RSA_PKCS = 0x00000001
CKM_RSA_PKCS_OAEP = 0x00000009
CKM_SHA256_RSA_PKCS = 0x00000040
CKM_SHA512_RSA_PKCS = 0x00000044
CKM_RSA_PKCS_PSS = 0x0000000D

# Key types
CKK_RSA = 0x00000000
# CKK_ML_DSA = ??? — does not exist in PKCS#11 v3.1

# Attribute types
CKA_MODULUS = 0x00000120
CKA_PUBLIC_EXPONENT = 0x00000122


def enumerate_hsm_rsa_keys(slot_id: int, pin: str = None) -> list:
    """List all RSA key objects in an HSM slot via PKCS#11.

    C_FindObjects with CKA_KEY_TYPE = CKK_RSA. The modulus (CKA_MODULUS)
    is a public attribute — readable without authentication on most HSMs.
    """
    print(f"[*] C_OpenSession(slot={slot_id})")
    if pin:
        print(f"[*] C_Login(CKU_USER) — but CKA_MODULUS is public anyway")
    keys = [
        {"label": "CA-Root-Key", "bits": 4096, "id": b"\x01"},
        {"label": "TLS-Server-Key", "bits": 2048, "id": b"\x02"},
        {"label": "Code-Signing-Key", "bits": 2048, "id": b"\x03"},
        {"label": "DNSSEC-KSK", "bits": 2048, "id": b"\x04"},
    ]
    for k in keys:
        print(f"    found CKK_RSA {k['bits']}-bit: {k['label']}")
    return keys


def extract_modulus(slot_id: int, key_id: bytes) -> tuple:
    """Read CKA_MODULUS and CKA_PUBLIC_EXPONENT from an HSM key object."""
    print(f"[*] C_GetAttributeValue(CKA_MODULUS, CKA_PUBLIC_EXPONENT) for key {key_id.hex()}")
    # placeholder values
    n = 17 * 19
    e = 65537
    return n, e


def factor_hsm_key(factorer: PolynomialFactorer, n: int, e: int, label: str):
    """Factor an RSA key that the HSM was supposed to protect."""
    print(f"[*] factoring {label} (n = {n.bit_length()}-bit modulus)...")
    p, q = factorer.factor_rsa_modulus(n)
    d = factorer.recover_private_exponent(n, e)
    print(f"[*] {label}: private key derived from public modulus")
    print(f"[*] HSM boundary bypassed — key never extracted, just derived")
    return d


def forge_ca_certificate(factorer: PolynomialFactorer, n: int, e: int,
                         subject_cn: str) -> bytes:
    """Issue a forged certificate using the CA key stored in the HSM."""
    d = factorer.recover_private_exponent(n, e)
    print(f"[*] issuing forged cert: CN={subject_cn}")
    print(f"[*] signed with CA private key derived from CKA_MODULUS")
    return b"forged-cert-der"


def sign_with_derived_key(factorer: PolynomialFactorer, n: int, e: int,
                          data: bytes, mechanism: int = CKM_SHA256_RSA_PKCS) -> bytes:
    """Sign data as if calling C_Sign() on the HSM — but without the HSM."""
    d = factorer.recover_private_exponent(n, e)
    print(f"[*] signing with derived key (mechanism CKM={mechanism:#010x})")
    # textbook RSA sign
    import hashlib
    h = int.from_bytes(hashlib.sha256(data).digest(), "big")
    sig = pow(h, d, n)
    return sig.to_bytes((n.bit_length() + 7) // 8, "big")


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== PKCS#11 HSM key derivation (SoftHSMv2 / Luna / CloudHSM) ===")
    print("    PKCS#11 v3.1: zero PQC mechanism types defined")
    print("    CKM_ML_DSA, CKK_ML_DSA — do not exist")
    print()

    print("[1] enumerating RSA keys in HSM slot 0...")
    keys = enumerate_hsm_rsa_keys(slot_id=0)

    print("[2] extracting public modulus (CKA_MODULUS — always readable)...")
    n, e = extract_modulus(0, b"\x01")

    print("[3] factoring CA-Root-Key...")
    d = factor_hsm_key(f, n, e, "CA-Root-Key")
    print("    this key protects: browser-trusted TLS, code signing, DNSSEC")

    print("[4] forging certificate with derived CA key...")
    forge_ca_certificate(f, n, e, "*.evil.example.com")
    print("    browser trusts this cert — chains to HSM-backed root")

    print("[5] signing arbitrary data without HSM access...")
    sig = sign_with_derived_key(f, n, e, b"malicious payload")
    print("    equivalent to C_Sign(CKM_SHA256_RSA_PKCS) on the HSM")
    print()
    print("[*] the HSM's physical security is irrelevant")
    print("[*] FIPS 140-3 Level 3 tamper response protects extraction")
    print("[*] factoring derives the key from the public half — no extraction needed")
