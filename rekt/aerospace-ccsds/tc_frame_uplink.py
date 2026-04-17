"""
tc_frame_uplink.py

Ground-station uplink flow: build a CCSDS TC (Telecommand) frame,
wrap it with SDLS (Space Data Link Security) headers, attach an
RSA-2048 PKCS#1 v1.5 signature, and transmit to a satellite.

This is the shape of the code running at ESA/ESOC's mission operations
control (MOC), NASA JPL / Goddard, Airbus / Thales Alenia Space control
centers, and commercial constellation operators (Iridium NEXT, SES O3b
mPOWER, OneWeb) whose platforms implement CCSDS 355.0-B SDLS Extended
Procedures.

Signing primitives live in `ccsds_sdls_ep.c`; this is the caller.
"""

import struct
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


CCSDS_TC_VERSION      = 0b00
CCSDS_TC_TYPE_CMD     = 0b1
SDLS_HEADER_LEN       = 6
SDLS_TRAILER_LEN      = 260   # SPI + IV/nonce + MAC + RSA-2048 signature


def build_tc_frame(spacecraft_id: int,
                    virtual_channel: int,
                    command_bytes: bytes,
                    spi: int,
                    signing_key: rsa.RSAPrivateKey) -> bytes:
    """Return a complete CCSDS TC + SDLS-wrapped frame."""
    # TC Primary Header (5 octets)
    length = 5 + SDLS_HEADER_LEN + len(command_bytes) + SDLS_TRAILER_LEN - 1
    primary = struct.pack(">HH B",
        ((CCSDS_TC_VERSION & 0x3) << 14) | (CCSDS_TC_TYPE_CMD << 13) |
          (0 << 12) | (spacecraft_id & 0x3FF),
        ((virtual_channel & 0x3F) << 10) | (length & 0x3FF),
        0)   # frame sequence number

    # SDLS Security Header
    sdls_header = struct.pack(">HI", spi, int(time.time()))  # SPI + seqnum

    payload = primary + sdls_header + command_bytes

    # RSA-2048 signature over the signed region (primary + sdls header
    # + command bytes). Real SDLS EP uses HMAC-SHA-256 over every frame
    # plus periodic RSA-signed key-update / OTAR frames — this mirrors
    # the key-update path which is purely RSA-signed.
    signature = signing_key.sign(
        payload,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    trailer = sdls_header[:4] + signature   # 4-byte MAC stub + RSA sig
    return payload + trailer


def uplink_command_sequence(spacecraft_id: int,
                              commands: list,
                              signing_key_pem: bytes,
                              transmit_callback) -> None:
    """
    Typical mission-ops sequence. Each command in `commands` becomes a
    signed TC frame; frames are handed to `transmit_callback` (e.g.,
    the ESA TM/TC Frontend or NASA DSN interface) for RF modulation.
    """
    key = serialization.load_pem_private_key(signing_key_pem, password=None)

    for cmd in commands:
        frame = build_tc_frame(
            spacecraft_id=spacecraft_id,
            virtual_channel=cmd["vc"],
            command_bytes=cmd["opcode"] + cmd["operands"],
            spi=cmd.get("spi", 1),
            signing_key=key,
        )
        transmit_callback(frame)
        time.sleep(0.1)   # CCSDS frame spacing


# Example: OTAR (Over-The-Air Rekey) — the one mission-critical command
# where RSA is doing the heavy lifting. An OTAR command updates the
# symmetric MAC/encryption key on the spacecraft's SDLS unit. The new
# key material is RSA-OAEP-wrapped under the spacecraft's embedded
# RSA-2048 public key and the command itself is RSA-PSS signed by
# the mission ops signing key. Factor either and attackers can rekey
# the bird to keys they control.
OTAR_COMMAND_OPCODE = b"\xC0\x01"
