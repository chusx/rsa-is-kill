"""
Factor any RSA root CA key trusted by Mozilla NSS to forge TLS certificates
accepted by Firefox (1.5B installs), Thunderbird S/MIME, and every RHEL system
tool (yum, dnf, curl) — complete MitM with green padlock, no warnings.
"""

import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

import hashlib

# Target: any RSA root CA in the Mozilla trust store (certdata.txt)
_demo = generate_demo_target()
ROOT_CA_PUBKEY_PEM = _demo["pub_pem"]
ROOT_CA_SUBJECT = "CN=DigiCert Global Root G2, OU=www.digicert.com, O=DigiCert Inc"


def extract_root_ca_from_nss_store() -> bytes:
    """Extract RSA root CA from NSS trust store (/etc/pki/nssdb/).

    The Mozilla root program distributes certdata.txt with ~150 root CAs.
    Most are RSA-2048 or RSA-4096. All are public by design.
    """
    return ROOT_CA_PUBKEY_PEM


def factor_root_ca(pubkey_pem: bytes) -> bytes:
    """Factor the root CA RSA key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def forge_tls_cert(domain: str, forged_ca_privkey: bytes) -> dict:
    """Forge a TLS certificate for any domain, chained to the factored root.

    Firefox NSS validates the chain. The forged cert passes all checks:
    - Chain to trusted root: yes (factored root signs our intermediate)
    - Subject/SAN match: yes (we control the cert content)
    - Validity period: yes (we set it)
    - CT logs: would need to be bypassed separately
    """
    return {
        "subject": f"CN={domain}",
        "issuer": ROOT_CA_SUBJECT,
        "validity": "2026-04-15 to 2027-04-15",
        "key_type": "RSA-2048 (or ECDSA — either works under a forged CA)",
    }


def forge_smime_cert(email: str, forged_ca_privkey: bytes) -> dict:
    """Forge an S/MIME certificate for any email address.

    Thunderbird uses NSS to verify S/MIME signatures. A forged
    S/MIME cert under the factored root CA shows 'Verified Sender'
    on phishing email.
    """
    return {
        "subject": f"E={email}",
        "smime_capability": "RSA-SHA256 signing + encryption",
        "thunderbird_display": "Verified Sender badge",
    }


def mitm_rhel_package_manager(forged_ca_privkey: bytes) -> dict:
    """MitM RHEL yum/dnf using a forged TLS cert for repo server.

    RHEL system tools use NSS for TLS. Forge a cert for the repo
    server, intercept package downloads, serve backdoored RPMs.
    """
    return {
        "target": "cdn.redhat.com",
        "attack": "TLS MitM via forged NSS-trusted cert",
        "payload": "backdoored rpm packages served to all RHEL systems",
    }


def forge_libreoffice_doc_signature(forged_ca_privkey: bytes) -> dict:
    """Forge a LibreOffice document digital signature via NSS PKCS#11.

    LibreOffice uses NSS for document signing. A cert under the
    factored root signs any document with a 'Valid Signature' indicator.
    """
    return {
        "document": "contract.odt",
        "signature": "Valid — signed by trusted certificate",
        "nsm_mechanism": "CKM_RSA_PKCS via NSS PKCS#11",
    }


if __name__ == "__main__":
    print("[1] Extracting RSA root CA from NSS trust store")
    pubkey = extract_root_ca_from_nss_store()
    print(f"    Root: {ROOT_CA_SUBJECT}")

    print("[2] Factoring root CA RSA key")
    forged_priv = factor_root_ca(pubkey)
    print("    Root CA private key recovered")

    print("[3] Forging TLS cert for google.com")
    tls_cert = forge_tls_cert("google.com", forged_priv)
    print(f"    {tls_cert}")
    print("    Firefox: green padlock, no warning, complete MitM")

    print("[4] Forging S/MIME cert for Thunderbird phishing")
    smime = forge_smime_cert("ceo@bigcorp.com", forged_priv)
    print(f"    {smime}")

    print("[5] MitM RHEL package manager")
    rhel = mitm_rhel_package_manager(forged_priv)
    print(f"    {rhel}")

    print("[6] Forging LibreOffice document signature")
    doc = forge_libreoffice_doc_signature(forged_priv)
    print(f"    {doc}")

    print("\n[*] NSS serves 1.5B Firefox users + entire RHEL ecosystem")
    print("    ML-KEM protects session keys but NOT cert authentication")
    print("    RSA cert chain verification: the part that proves identity")
