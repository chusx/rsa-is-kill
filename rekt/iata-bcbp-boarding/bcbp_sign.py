"""
bcbp_sign.py

IATA Bar Coded Boarding Pass (BCBP) — digital signature per Resolution 792.
Sources:
  - IATA Resolution 792 v9 (2023) — Bar Coded Boarding Pass
  - IATA Passenger Services Conference Resolutions Manual (PSCRM)
  - ICAO 9303 Part 13 (machine readable travel documents, referenced)
  - FAA AC 150/5200-28 (airport security; references BCBP verification)
  - TSA Security Directive 1542-04-08 (Secure Flight + BCBP verification)

BCBP payload structure (PDF417 barcode):

  M1 mandatory (60 bytes):
    Format code 'M' | # of legs (1-9) | passenger name (20) |
    Electronic ticket indicator | operating carrier PNR code (7) |
    From city code (3) | To city code (3) | Operating carrier (3) |
    Flight number (5) | Date of flight (3, Julian) | Compartment code (1) |
    Seat number (4) | Check-in sequence (5) | Passenger status (1)

  Conditional fields (variable):
    Version number | Field size of unique conditional items | ...
    Size of FF airline/# | FF #/Selectee indicator | International
    documents verification | Marketing carrier designator | ...

  Security data (variable):
    '>' marker | Version number | Size of security data |
    Type of security data ('0' = no signature, '1' = RSA signature,
    '2' = ICAO 9303 signature, '3' = hybrid) | Size of issuing system |
    Airline Numeric Code (IATA 3-digit) | Key reference |
    Signature (base32-encoded, typically 128 or 256 bytes for RSA-1024/2048)
"""

import base64
import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


def parse_bcbp(bcbp_text: str) -> dict:
    """Parse a BCBP M1 payload into structured fields."""
    if not bcbp_text.startswith("M"):
        raise ValueError("Not a BCBP (must start with 'M')")

    num_legs = int(bcbp_text[1])
    name_raw = bcbp_text[2:22].strip()
    # Name format: "LAST/FIRSTMIDDLE" in the 20-byte field, space-padded
    last, _, given = name_raw.partition("/")

    etkt_indicator = bcbp_text[22]
    pnr = bcbp_text[23:30].strip()
    origin = bcbp_text[30:33]
    destination = bcbp_text[33:36]
    operating_carrier = bcbp_text[36:39].strip()
    flight_number = bcbp_text[39:44].strip()
    julian_date = int(bcbp_text[44:47])
    compartment = bcbp_text[47]
    seat = bcbp_text[48:52].strip()
    check_in_seq = bcbp_text[52:57].strip()
    pax_status = bcbp_text[57]

    # Security data: starts with '^' marker (since v5) or '>' (older)
    security_idx = bcbp_text.find("^")
    if security_idx < 0:
        security_idx = bcbp_text.find(">")
    security_data = bcbp_text[security_idx:] if security_idx >= 0 else None

    return {
        "name_last": last, "name_given": given,
        "pnr": pnr, "origin": origin, "destination": destination,
        "carrier": operating_carrier, "flight": flight_number,
        "date": julian_date, "compartment": compartment,
        "seat": seat, "sequence": check_in_seq,
        "passenger_status": pax_status,
        "security_data": security_data,
        "signable_portion": bcbp_text[:security_idx] if security_idx >= 0
                            else bcbp_text,
    }


def sign_bcbp(bcbp_signable: str,
               rsa_private_key: rsa.RSAPrivateKey,
               airline_iata_numeric: str,
               key_reference: str = "00") -> str:
    """
    Append IATA-792 security data with RSA-SHA256 signature.

    The signature input is the ASCII BCBP from position 0 up to (but not
    including) the security data marker. Hash: SHA-256. Padding: PKCS#1 v1.5.
    """
    digest = hashes.Hash(hashes.SHA256())
    digest.update(bcbp_signable.encode("ascii"))
    hashed = digest.finalize()

    signature = rsa_private_key.sign(
        bcbp_signable.encode("ascii"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    sig_b32 = base64.b32encode(signature).decode("ascii").rstrip("=")
    sig_size_hex = f"{len(sig_b32):02X}"

    # Security header (simplified — real header has more sub-fields)
    #  ^ version=6 | totalSize=XXX | type=1 (RSA) | issuerSize=3 | issuer=XXX |
    #  keyRef=XX | signature=...
    security = (
        f"^6"
        f"{len(sig_b32) + 12:03X}"  # total size of security data
        f"1"                         # type 1 = RSA signature
        f"003{airline_iata_numeric}"  # 3-byte airline IATA numeric code
        f"{key_reference}"
        f"{sig_size_hex}{sig_b32}"
    )
    return bcbp_signable + security


def verify_bcbp(bcbp_text: str,
                 iata_ksa_trust_store: dict) -> bool:
    """
    Verify a BCBP signature using the airline's public key from the IATA
    Key Signing Authority trust store.

    The trust store is distributed by IATA to all signatories (airlines,
    airports, TSA, CBP, ground handlers). It maps (airline_iata_numeric,
    key_reference) -> RSAPublicKey.

    This is the verification that TSA Secure Flight, self-boarding gates,
    and mobile wallet apps perform.
    """
    parsed = parse_bcbp(bcbp_text)
    if not parsed["security_data"]:
        return False

    sec = parsed["security_data"]
    # Parse security header — indices per Resolution 792 v9
    airline_numeric = sec[7:10]
    key_ref = sec[10:12]
    sig_size = int(sec[12:14], 16)
    sig_b32 = sec[14:14 + sig_size]

    # Re-pad base32
    pad_len = (8 - len(sig_b32) % 8) % 8
    signature = base64.b32decode(sig_b32 + "=" * pad_len)

    # Look up airline public key
    key_id = (airline_numeric, key_ref)
    if key_id not in iata_ksa_trust_store:
        return False
    pubkey = iata_ksa_trust_store[key_id]

    try:
        pubkey.verify(
            signature,
            parsed["signable_portion"].encode("ascii"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def issue_precheck_bcbp(airline_key: rsa.RSAPrivateKey,
                          airline_iata_numeric: str,
                          passenger_name: str, pnr: str,
                          origin: str, destination: str,
                          flight: str, date: datetime.date,
                          seat: str, ktn: str) -> str:
    """
    Build a signed BCBP with TSA PreCheck indicator set.

    The PreCheck indicator lives in the "Selectee indicator" conditional
    subfield. When the airline signs a BCBP with PreCheck=1, TSA lane
    scanners route the passenger to PreCheck lanes without additional
    screening.

    A factoring attack against the airline's RSA signing key produces
    valid-signed PreCheck BCBPs for anyone — including individuals TSA
    has not vetted. The PreCheck trust model assumes the signing key is
    private; factoring breaks that assumption.
    """
    julian = date.timetuple().tm_yday
    name_field = f"{passenger_name:<20}"[:20]

    # Build M1 payload (simplified; real BCBP has conditional fields)
    m1 = (
        "M1"
        f"{name_field}"
        "E"                              # E-ticket indicator
        f"{pnr:<7}"[:7]
        f"{origin:<3}"[:3]
        f"{destination:<3}"[:3]
        f"{airline_iata_numeric:<3}"[:3]  # using numeric code as carrier
        f"{flight:<5}"[:5]
        f"{julian:03d}"
        "Y"                              # compartment (economy)
        f"{seat:<4}"[:4]
        f"{'0001':<5}"                   # check-in sequence
        "1"                              # passenger status (checked in)
    )
    # Conditional field with Selectee indicator = '3' (PreCheck-eligible)
    # per TSA Secure Flight guidance, encoded in BCBP per IATA 792.
    conditional = f">{ktn:<15}3"

    signable = m1 + conditional
    return sign_bcbp(signable, airline_key, airline_iata_numeric)


# IATA Key Signing Authority (KSA):
#
# The KSA is a trusted third party operated by IATA HQ in Montreal.
# Airlines submit their public keys annually; KSA bundles them into a
# signed "Digital Signing Authority Public Key Inventory" file that is
# distributed to:
#   - TSA (for Secure Flight and CAT-2 e-gate verification)
#   - CBP (for APIS boarding pass cross-checks)
#   - ICAO PKD-connected regulators
#   - Airport ground handlers (SITA, Amadeus, Sabre via DCS)
#   - Self-boarding gate vendors (Vision-Box, Materna, Indra)
#
# The KSA itself signs its bulletin with an RSA key. Compromise of the
# KSA root means an attacker can issue fake airline public keys that
# are accepted into the trust store, no factoring of individual airline
# keys needed.
#
# Legacy RSA-1024 airline keys are still accepted in the current trust
# store; key rotation is not retroactive. A 2014-era RSA-1024 BCBP
# signing key is factorable classically today with enough compute; a
# novel poly-time factoring algorithm makes it trivial and extends the
# attack surface to every RSA-2048 airline key.
