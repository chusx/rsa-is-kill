"""
poly_factor.py — Hypothetical polynomial-time integer factorisation.

This module provides the public interface that every rekt/<example>/rekt.py
imports to break RSA keys.  The algorithm itself is a placeholder (trial
division up to a tiny bound, then gives up); the *interface* is what matters:
    from poly_factor import PolynomialFactorer

    f = PolynomialFactorer()
    p, q = f.factor_rsa_modulus(n)          # n = p·q
    d    = f.recover_private_exponent(n, e) # CRT private exponent
    key  = f.reconstruct_privkey(pubkey)    # PEM-in → PEM-out

Threat model: a classical (non-quantum) polynomial-time algorithm for
integer factorisation is published.  ECDSA / Ed25519 / ECDH survive.
Only RSA is dead.
"""

from __future__ import annotations

import math
import struct
from typing import Optional, Tuple

# ---------------------------------------------------------------------------
# Demo key generator — produces a small RSA key that trial division can
# factor, so every rekt.py can run end-to-end without a real algorithm.
# ---------------------------------------------------------------------------

_DEMO_P = 65537_00001  # not a real prime; we'll use cryptography to make one
_DEMO_BITS = 512       # tiny — factorable by trial division up to 1M? No,
                       # but we store p,q so the demo factorer can cheat.

def generate_demo_target(bits: int = 512) -> dict:
    """Generate a small RSA keypair for demo/test purposes.

    Returns dict with keys: pub_pem, priv_pem, n, e, p, q.
    The PolynomialFactorer's trial_division won't factor 512-bit keys,
    so we register (n → p,q) in a cheat-sheet the factorer consults.
    """
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat, PrivateFormat, NoEncryption,
    )
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pub = priv.public_key()
    pn = priv.private_numbers()
    result = {
        "pub_pem": pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo),
        "priv_pem": priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()),
        "n": pn.public_numbers.n,
        "e": pn.public_numbers.e,
        "p": pn.p,
        "q": pn.q,
    }
    _DEMO_CHEATSHEET[result["n"]] = (result["p"], result["q"])
    return result

_DEMO_CHEATSHEET: dict = {}


class PolynomialFactorer:
    """Hypothetical O(n^k) factoring oracle.

    In reality this is just trial division behind the API so the
    surrounding PoC scaffolding can call real methods and get back
    plausible types.  Swap the guts for the real thing if you find it.
    """

    def __init__(self, *, threads: int = 1, log_level: int = 0):
        self._threads = threads
        self._log = log_level

    # ------------------------------------------------------------------
    # Core: factor a raw modulus
    # ------------------------------------------------------------------

    def factor_rsa_modulus(self, n: int) -> Tuple[int, int]:
        """Return (p, q) such that p * q == n.

        Raises ValueError if n is prime or if the placeholder can't
        factor it (real algorithm would never fail on a semiprime).
        """
        if n < 4:
            raise ValueError("not a valid RSA modulus")

        if n in _DEMO_CHEATSHEET:
            return _DEMO_CHEATSHEET[n]

        p = self._trial_division(n)
        if p is None:
            # -- THIS IS WHERE THE REAL ALGORITHM GOES --
            raise NotImplementedError(
                "placeholder: real poly-time algorithm not implemented; "
                f"could not factor {n.bit_length()}-bit modulus"
            )
        q, rem = divmod(n, p)
        assert rem == 0
        return (p, q) if p <= q else (q, p)

    # ------------------------------------------------------------------
    # RSA private-key recovery helpers
    # ------------------------------------------------------------------

    def recover_private_exponent(
        self, n: int, e: int = 0x10001
    ) -> int:
        """Given (n, e), return d such that e·d ≡ 1 (mod λ(n))."""
        p, q = self.factor_rsa_modulus(n)
        lam = self._carmichael(p, q)
        return pow(e, -1, lam)

    def recover_crt_components(
        self, n: int, e: int = 0x10001
    ) -> dict:
        """Return the full CRT quintuple {p, q, d, dp, dq, qinv}."""
        p, q = self.factor_rsa_modulus(n)
        lam = self._carmichael(p, q)
        d = pow(e, -1, lam)
        dp = d % (p - 1)
        dq = d % (q - 1)
        qinv = pow(q, -1, p)
        return dict(p=p, q=q, d=d, dp=dp, dq=dq, qinv=qinv, n=n, e=e)

    def reconstruct_privkey(
        self,
        pubkey_pem: bytes,
        fmt: str = "pem",
    ) -> bytes:
        """PEM/DER RSA public key in → PEM RSA private key out.

        Requires `cryptography` (pip install cryptography).
        """
        from cryptography.hazmat.primitives.asymmetric.rsa import (
            rsa_crt_dmp1,
            rsa_crt_dmq1,
            rsa_crt_iqmp,
            RSAPrivateNumbers,
            RSAPublicNumbers,
        )
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            load_der_public_key,
            load_pem_public_key,
        )

        loader = load_pem_public_key if fmt == "pem" else load_der_public_key
        pub = loader(pubkey_pem)
        pub_numbers: RSAPublicNumbers = pub.public_numbers()

        n, e = pub_numbers.n, pub_numbers.e
        p, q = self.factor_rsa_modulus(n)
        d = pow(e, -1, self._carmichael(p, q))

        priv_numbers = RSAPrivateNumbers(
            p=p,
            q=q,
            d=d,
            dmp1=rsa_crt_dmp1(d, p),
            dmq1=rsa_crt_dmq1(d, q),
            iqmp=rsa_crt_iqmp(p, q),
            public_numbers=pub_numbers,
        )
        return (
            priv_numbers.private_key()
            .private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        )

    # ------------------------------------------------------------------
    # Signing / decryption with the recovered key
    # ------------------------------------------------------------------

    def forge_pkcs1v15_signature(
        self,
        pubkey_pem: bytes,
        message: bytes,
        hash_algo: str = "sha256",
    ) -> bytes:
        """Sign `message` using a forged private key derived from pubkey."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        algo_map = {
            "sha256": hashes.SHA256(),
            "sha384": hashes.SHA384(),
            "sha512": hashes.SHA512(),
            "sha1": hashes.SHA1(),
        }
        priv_pem = self.reconstruct_privkey(pubkey_pem)
        priv = load_pem_private_key(priv_pem, password=None)
        return priv.sign(message, padding.PKCS1v15(), algo_map[hash_algo])

    def forge_pss_signature(
        self,
        pubkey_pem: bytes,
        message: bytes,
        hash_algo: str = "sha256",
        salt_length: Optional[int] = None,
    ) -> bytes:
        """Sign `message` with RSA-PSS using a forged private key."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        algo_map = {
            "sha256": hashes.SHA256(),
            "sha384": hashes.SHA384(),
            "sha512": hashes.SHA512(),
        }
        h = algo_map[hash_algo]
        sl = salt_length if salt_length is not None else padding.PSS.AUTO
        priv_pem = self.reconstruct_privkey(pubkey_pem)
        priv = load_pem_private_key(priv_pem, password=None)
        return priv.sign(message, padding.PSS(padding.MGF1(h), sl), h)

    def decrypt_rsa_oaep(
        self,
        pubkey_pem: bytes,
        ciphertext: bytes,
        hash_algo: str = "sha256",
    ) -> bytes:
        """Decrypt an RSA-OAEP ciphertext using a forged private key."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        algo_map = {
            "sha256": hashes.SHA256(),
            "sha1": hashes.SHA1(),
        }
        h = algo_map[hash_algo]
        priv_pem = self.reconstruct_privkey(pubkey_pem)
        priv = load_pem_private_key(priv_pem, password=None)
        return priv.decrypt(ciphertext, padding.OAEP(padding.MGF1(h), h, None))

    def raw_rsa_decrypt(self, n: int, e: int, ciphertext_int: int) -> int:
        """Textbook RSA decryption: m = c^d mod n."""
        d = self.recover_private_exponent(n, e)
        return pow(ciphertext_int, d, n)

    # ------------------------------------------------------------------
    # X.509 / PEM convenience
    # ------------------------------------------------------------------

    def factor_from_cert_pem(self, cert_pem: bytes) -> Tuple[int, int]:
        """Extract RSA modulus from an X.509 PEM cert and factor it."""
        from cryptography.x509 import load_pem_x509_certificate

        cert = load_pem_x509_certificate(cert_pem)
        n = cert.public_key().public_numbers().n
        return self.factor_rsa_modulus(n)

    def privkey_from_cert_pem(self, cert_pem: bytes) -> bytes:
        """X.509 PEM cert in → forged PEM private key out."""
        from cryptography.x509 import load_pem_x509_certificate
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        cert = load_pem_x509_certificate(cert_pem)
        pub_pem = cert.public_key().public_bytes(Encoding.PEM, PublicFormat.PKCS1)
        return self.reconstruct_privkey(pub_pem)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _carmichael(p: int, q: int) -> int:
        return (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)

    @staticmethod
    def _trial_division(n: int, bound: int = 1_000_000) -> Optional[int]:
        if n % 2 == 0:
            return 2
        d = 3
        while d * d <= n and d <= bound:
            if n % d == 0:
                return d
            d += 2
        return None
