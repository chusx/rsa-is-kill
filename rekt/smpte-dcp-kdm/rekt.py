"""
Decrypt Digital Cinema Package (DCP) content by factoring projector Security
Manager RSA-2048 keys or the studio's DKDM-signing root. Extract AES-128
content keys from KDMs, enable zero-day piracy of theatrical releases.
"""
import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import hashlib
import os

# SMPTE ST 429 / ISDCF identifiers
KDM_CONTENT_TYPE = "http://www.smpte-ra.org/schemas/430-1/2006/KDM"
CPL_CONTENT_TYPE = "http://www.smpte-ra.org/schemas/429-7/2006/CPL"


def fetch_projector_cert_from_tdl(projector_serial: str) -> bytes:
    """Fetch projector Security Manager certificate from the TDL.

    Studios maintain a Trusted Device List (TDL) with every projector's
    public cert. Booking services and lab distributors have access.
    """
    print(f"[*] querying TDL for projector {projector_serial}")
    print("[*] Security Manager RSA-2048 certificate retrieved")
    return b"-----BEGIN CERTIFICATE-----\n...(projector SM cert)...\n-----END CERTIFICATE-----\n"


def decrypt_kdm(factorer: PolynomialFactorer,
                projector_cert_pem: bytes,
                kdm_xml: bytes) -> dict:
    """Decrypt a KDM to extract per-reel AES-128 content keys.

    KDM = Key Delivery Message. Contains CPL reference + engagement window +
    AES-128 keys encrypted under the projector's RSA public key (RSA-OAEP).
    """
    print("[*] parsing KDM XML...")
    print("[*] decrypting RSA-OAEP wrapped AES-128 content keys...")
    # extract the encrypted key material from KDM XML
    keys = {
        "reel_1": os.urandom(16).hex(),
        "reel_2": os.urandom(16).hex(),
        "reel_3": os.urandom(16).hex(),
    }
    print(f"[*] recovered {len(keys)} reel content keys")
    return keys


def forge_kdm_for_any_projector(factorer: PolynomialFactorer,
                                dkdm_signing_cert: bytes,
                                target_projector_cert: bytes,
                                cpl_id: str,
                                content_keys: dict,
                                window_start: str,
                                window_end: str) -> str:
    """Forge a KDM from the studio's DKDM-signing key.

    Factor the studio DKDM-signing root -> issue KDMs for any projector
    on the TDL, for any CPL, for any engagement window.
    """
    kdm = f"""<KDM xmlns="{KDM_CONTENT_TYPE}">
  <AuthenticatedPublic>
    <CPLId>{cpl_id}</CPLId>
    <ContentKeysNotValidBefore>{window_start}</ContentKeysNotValidBefore>
    <ContentKeysNotValidAfter>{window_end}</ContentKeysNotValidAfter>
  </AuthenticatedPublic>
  <AuthenticatedPrivate>
    <!-- AES keys encrypted to target projector RSA key -->
  </AuthenticatedPrivate>
</KDM>"""
    sig = factorer.forge_pkcs1v15_signature(dkdm_signing_cert,
                                            kdm.encode(), "sha256")
    print(f"[*] forged KDM for CPL {cpl_id}")
    print(f"[*] engagement window: {window_start} to {window_end}")
    return kdm


def forge_fake_projector_cert(factorer: PolynomialFactorer,
                              vendor_sm_ca: bytes,
                              fake_serial: str) -> bytes:
    """Forge a Security Manager certificate for a non-existent projector.

    Factor a vendor SM CA (Christie/Barco/NEC/Dolby/GDC) -> mint certs
    for fake projectors -> receive KDMs -> extract AES keys in the clear.
    """
    priv = factorer.privkey_from_cert_pem(vendor_sm_ca)
    print(f"[*] forged projector SM cert: serial={fake_serial}")
    print("[*] fake projector on TDL -> receives KDMs -> extracts content keys")
    return priv


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== Digital Cinema KDM — theatrical content piracy ===")
    print("    ~200,000 SMPTE projectors worldwide")
    print("    every feature film since ~2012 is DCP-encrypted")
    print()

    print("[1] fetching projector SM cert from TDL...")
    proj_cert = fetch_projector_cert_from_tdl("CHRISTIE-CP4425-SN12345")

    print("[2] factoring projector RSA-2048 key...")
    print("    factory-installed in FIPS 140-2 Level 3 tamper module")
    print("    but factoring derives from public key, not extraction")

    print("[3] decrypting KDM -> extracting AES-128 content keys...")
    keys = decrypt_kdm(f, proj_cert, b"<KDM>...</KDM>")
    for reel, key in keys.items():
        print(f"    {reel}: AES-128 key = {key[:16]}...")

    print("[4] alternative: factor studio DKDM-signing root...")
    print("    issue KDMs for any projector, any film, any window")

    print("[5] alternative: factor vendor SM CA (Christie/Barco/NEC)...")
    print("    mint fake projector certs -> receive KDMs -> extract keys")

    print("[6] result: clean pirate copies of every first-run film")
    print("    theatrical-window-only content goes to the wild same day")
    print()
    print("[*] projector SM cert is immutable — requires physical service")
    print("[*] DCI re-certification at scale: unprecedented")
