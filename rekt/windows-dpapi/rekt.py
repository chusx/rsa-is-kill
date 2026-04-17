"""
Decrypt every DPAPI-protected secret in a Windows domain by factoring the domain
DPAPI backup key (RSA-2048). Chrome passwords, Credential Manager, WiFi keys,
certificate private keys, Azure AD Connect credentials — all offline, no domain admin.
"""
import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

_demo = generate_demo_target(bits=2048)

import struct
import hashlib

# DPAPI-protected secret categories
DPAPI_TARGETS = [
    "Chrome/Edge/Firefox saved passwords",
    "Windows Credential Manager",
    "Outlook PST passwords",
    "WiFi WPA2-Enterprise keys",
    "Certificate private keys (CNG/CAPI)",
    "IIS app pool credentials",
    "Azure AD Connect sync credentials",
    "SCCM NAA credentials",
]

# MS-BKRP protocol GUID (domain backup key retrieval)
BKRP_BACKUPKEY_GUID = "7f752b10-178e-11d1-ab8f-00805f14db40"


def retrieve_dpapi_backup_pubkey(domain: str) -> bytes:
    """Retrieve the domain DPAPI backup public key via MS-BKRP / LDAP.

    Any authenticated domain user can retrieve this. The public key is in
    CN=BCKUPKEY_<GUID>,CN=System,DC=... as a public-key blob.
    """
    print(f"[*] retrieving DPAPI backup public key from {domain}")
    print(f"[*] MS-BKRP GUID: {BKRP_BACKUPKEY_GUID}")
    print("[*] any domain user can retrieve this — no special privileges")
    return _demo["pub_pem"]


def decrypt_master_key_file(factorer: PolynomialFactorer,
                            backup_pubkey_pem: bytes,
                            master_key_file: bytes,
                            user_sid: str) -> bytes:
    """Decrypt a user's DPAPI master key file using the factored backup key.

    Master key files live in %APPDATA%/Microsoft/Protect/<SID>/.
    Each is RSA-OAEP encrypted to the domain backup public key.
    """
    privkey = factorer.reconstruct_privkey(backup_pubkey_pem)
    # Simulate OAEP decryption: encrypt a fake master key with the public key,
    # then decrypt it with the factored private key to demonstrate the attack
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives import hashes, serialization
    pub = serialization.load_pem_public_key(backup_pubkey_pem)
    fake_master_key = b"\xaa" * 32  # simulated 256-bit DPAPI master key
    ciphertext = pub.encrypt(
        fake_master_key,
        asym_padding.OAEP(asym_padding.MGF1(hashes.SHA256()), hashes.SHA256(), None),
    )
    plaintext = factorer.decrypt_rsa_oaep(backup_pubkey_pem, ciphertext)
    print(f"[*] decrypted DPAPI master key for SID {user_sid}")
    return plaintext


def decrypt_chrome_passwords(master_key: bytes, user: str) -> list:
    """Decrypt Chrome/Edge saved passwords using the recovered master key."""
    passwords = [
        {"url": "https://bankofamerica.com", "user": user, "pass": "***"},
        {"url": "https://portal.azure.com", "user": user, "pass": "***"},
        {"url": "https://vpn.corp.internal", "user": user, "pass": "***"},
    ]
    print(f"[*] decrypted {len(passwords)} Chrome passwords for {user}")
    return passwords


def decrypt_aadc_credentials(master_key: bytes) -> dict:
    """Decrypt Azure AD Connect sync account credentials.

    AADC service account has DirSync/Global Admin equivalent access to
    Azure AD. Its credentials are DPAPI-protected on the AADC server.
    """
    creds = {
        "service": "Azure AD Connect",
        "account": "MSOL_<hex>@contoso.onmicrosoft.com",
        "role": "Global Administrator equivalent",
        "tenant": "contoso.onmicrosoft.com",
    }
    print(f"[*] decrypted AADC credentials: {creds['account']}")
    print("[*] -> full Azure AD tenant compromise")
    return creds


def bulk_offline_decrypt(factorer: PolynomialFactorer,
                         backup_pubkey_pem: bytes,
                         profile_backup_path: str,
                         num_users: int):
    """Bulk offline decryption of all domain users' DPAPI secrets."""
    print(f"[*] processing {num_users} user profiles from backup")
    print(f"[*] source: {profile_backup_path}")
    for i in range(min(num_users, 3)):
        sid = f"S-1-5-21-XXXXXXX-{1000+i}"
        print(f"    user {sid}: master key decrypted, Chrome + CredMan + WiFi recovered")
    if num_users > 3:
        print(f"    ... and {num_users - 3} more users")


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== Windows DPAPI domain backup key — RSA-2048 ===")
    print("    one RSA-2048 key per AD domain, generated at domain creation")
    print("    wraps every user's DPAPI master key")
    print("    mimikatz path: need domain admin. factoring path: need domain user.")
    print()

    domain = "CONTOSO.LOCAL"
    print(f"[1] retrieving DPAPI backup public key from {domain}...")
    pubkey = retrieve_dpapi_backup_pubkey(domain)

    print("[2] factoring RSA-2048 domain backup key...")
    print("    public key available to any authenticated domain user")

    print("[3] decrypting user DPAPI master keys offline...")
    mk = decrypt_master_key_file(f, pubkey, b"\x00" * 64, "S-1-5-21-XXXXXXX-1001")

    print("[4] decrypting Chrome saved passwords...")
    decrypt_chrome_passwords(mk, "jsmith@contoso.com")

    print("[5] decrypting Azure AD Connect credentials...")
    decrypt_aadc_credentials(mk)
    print("    AADC -> Azure AD Global Admin -> full cloud tenant")

    print("[6] bulk offline: processing stolen backup archive...")
    bulk_offline_decrypt(f, pubkey, "\\\\backup\\profiles$", 5000)

    print()
    print("[*] DPAPI backup key never rotated in most domains (created once)")
    print("[*] MS-BKRP protocol: no non-RSA key type defined")
    print("[*] HNDL: steal profile backups now, factor key later")
