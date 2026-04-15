"""
dcdm_kdm_rsa.py

DCI / SMPTE Digital Cinema Key Delivery Message parsing.
Sources:
  - DCI Digital Cinema System Specification v1.4.1 (2022)
  - SMPTE ST 430-1:2021 — Key Delivery Message (KDM)
  - SMPTE ST 430-2:2017 — Digital Certificate
  - SMPTE ST 430-3:2008 — Generic Extra-Theater Message Format
  - SMPTE ST 429-6 — MXF Track File Essence Encryption

Every commercial cinema projector holds an RSA-2048 keypair inside its
Security Manager (SM) module. The public key half is certified in a
SMPTE ST 430-2 X.509 certificate with DCI-specific extensions.

To screen a film:
  1. Studio ingests the DCP and generates random AES-128 Content Encryption
     Keys (CEKs), one per reel.
  2. Studio's KDM Generator fetches the target projector's SMPTE 430-2
     certificate, takes its RSA-2048 public key.
  3. For each CEK, an "ETM Cipher" block is built: CEK || metadata || timestamps,
     wrapped in RSAES-OAEP-MGF1(SHA-256) to the projector's RSA public key.
  4. All wrapped CEK blocks + authorization metadata are packaged in an XML
     KDM signed with XMLDSig RSA-2048 by the KDM Generator's cert.
  5. KDM XML emailed or served via the cinema booking platform. Projector
     imports the KDM, unwraps CEKs with its private RSA-2048 key, decrypts
     film content during playback.

Attack: factor the projector's RSA-2048 key. Every KDM sent to that
projector decrypts offline. Clean plaintext of every film ever shown.
"""

import base64
import xml.etree.ElementTree as ET
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509

KDM_NS = {
    "ds":    "http://www.w3.org/2000/09/xmldsig#",
    "enc":   "http://www.w3.org/2001/04/xmlenc#",
    "etm":   "http://www.smpte-ra.org/schemas/430-3/2006/ETM",
    "kdm":   "http://www.smpte-ra.org/schemas/430-1/2006/KDM",
}


def parse_kdm_xml(kdm_xml_bytes: bytes) -> dict:
    """
    Parse a SMPTE ST 430-1 KDM XML file.
    Returns dict with:
      - wrapped_keys: list of base64 RSAES-OAEP ciphertexts
      - signature: XMLDSig signature value
      - signer_cert: signer's X.509 cert (PEM)
      - target_recipient: the projector cert X509 thumbprint this KDM targets
    """
    root = ET.fromstring(kdm_xml_bytes)

    wrapped = []
    for cv in root.iter("{%s}CipherValue" % KDM_NS["enc"]):
        wrapped.append(base64.b64decode(cv.text))

    sig = root.find(".//ds:SignatureValue", KDM_NS)
    cert = root.find(".//ds:X509Certificate", KDM_NS)
    recip = root.find(".//kdm:Recipient/kdm:X509IssuerSerial", KDM_NS)

    return {
        "wrapped_keys": wrapped,
        "signature": base64.b64decode(sig.text) if sig is not None else None,
        "signer_cert_b64": cert.text if cert is not None else None,
        "recipient_issuer_serial": ET.tostring(recip) if recip is not None else None,
    }


def unwrap_content_keys(wrapped_keys: list[bytes],
                         projector_rsa_private_key) -> list[bytes]:
    """
    RSAES-OAEP-MGF1(SHA-256) unwrap of each Content Encryption Key.
    SMPTE ST 430-1 ETM Cipher block format (122 bytes):
      Structure ID (16)  || Signer Thumbprint (20) || CPL ID (16)
      || Not-Valid-Before (25) || Not-Valid-After (25) || Key Type (4)
      || Key ID (16) || Content Key (16)

    A factoring break recovers the projector's RSA-2048 private key from
    its SMPTE ST 430-2 public certificate — which is published in the
    Trusted Device List and routinely exchanged with distributors.
    """
    ceks = []
    for wrapped in wrapped_keys:
        etm_block = projector_rsa_private_key.decrypt(
            wrapped,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        # Last 16 bytes of the 122-byte ETM Cipher block = AES Content Key
        ceks.append(etm_block[-16:])
    return ceks


def verify_kdm_signature(kdm_xml_bytes: bytes,
                          signer_cert: x509.Certificate) -> bool:
    """
    XMLDSig RSA-2048 signature verification over the <AuthenticatedPublic>
    and <AuthenticatedPrivate> portions of the KDM.

    Real verification requires exclusive canonicalization (RFC 3741) of the
    signed elements, which xmlsec or signxml handles. Simplified here.
    """
    pub = signer_cert.public_key()
    # The signed info and signature value extraction elided for brevity.
    # Factoring the signer's RSA-2048 key lets an attacker forge KDMs for
    # any projector, authorizing any film for any screening window.
    return True


def decrypt_mxf_frame(encrypted_frame: bytes, cek: bytes,
                       iv: bytes) -> bytes:
    """
    SMPTE ST 429-6 frame-level AES-128-CBC decryption of MXF essence.
    With the CEK recovered via RSA-wrap unwrap, this is ordinary AES.
    """
    cipher = Cipher(algorithms.AES(cek), modes.CBC(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_frame) + decryptor.finalize()


# Projector trust anchors:
#
# The DCI Trusted Device List (TDL) is the registry of compliant projector
# Security Managers. Each entry lists:
#   - Projector manufacturer (NEC / Christie / Barco / Sony / GDC / Dolby)
#   - SM module serial number
#   - SMPTE ST 430-2 certificate (contains RSA-2048 public key)
#   - Compliance test report reference
#
# Studios fetch the target projector's public cert from the TDL (or from a
# booking-agent-provided CSV) before generating KDMs. The cert is PUBLIC by
# design — it has to be, since studios don't trust cinemas.
#
# This means: a classical factoring attacker has free access to every
# projector's RSA-2048 public key. The only defense is that factoring
# RSA-2048 requires more compute than anyone has today. A novel poly-time
# factoring algorithm removes that defense.
