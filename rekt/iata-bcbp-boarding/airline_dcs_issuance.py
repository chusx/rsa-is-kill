"""
airline_dcs_issuance.py

IATA BCBP (Bar Coded Boarding Pass, Resolution 792 / PADIS) issuance
flow from an airline DCS (Departure Control System).  Every boarding
pass a passenger receives — paper, Apple Wallet, Google Wallet,
airline app PDF, gate-printed thermal strip — is a BCBP string whose
conditional portion may include an RSA signature issued here.

DCS operators running this at scale: SITA DCS (Check & Print,
Horizon), Amadeus Altéa DCS (LH Group, BA, SQ, QF), Sabre SabreSonic
(American, Alaska, Aeroméxico, JetBlue), Navitaire (Ryanair,
easyJet, IndiGo, VietJet). Per-airline private RSA keys; IATA
distributes the public keys to TSA Secure Flight, CBSA, BAG ETD
readers, and gate Common Use Self Service kiosks.

Underlying signing/verifying primitives live in `bcbp_sign.py`.
"""

import datetime
import random
import string
from bcbp_sign import sign_bcbp_conditional, verify_bcbp_conditional


class DCSBoardingPassIssuer:
    def __init__(self, airline_iata: str, signing_key_pem: bytes,
                  dep_stn_local_tz):
        self.airline = airline_iata        # "BA", "AA", "LH", "DL", "UA"
        self.signing_key_pem = signing_key_pem
        self.dep_stn_local_tz = dep_stn_local_tz

    def _make_pnr(self) -> str:
        return "".join(random.choices(string.ascii_uppercase, k=6))

    def _julian(self, d: datetime.date) -> str:
        return f"{d.timetuple().tm_yday:03d}"

    def issue(self, *, name: str, flight: str, dep: str, arr: str,
              dep_date: datetime.date, seat: str, seq: int,
              ff_number: str | None = None,
              tsa_prechk_eligible: bool = False,
              global_entry_known: bool = False) -> str:
        """
        Return the BCBP M1 string.  Mandatory items, then conditional
        section, then (optional, for TSA PreCheck and CBP Trusted
        Traveler streams) a Version-8 signed segment.
        """
        pnr = self._make_pnr()
        mandatory = (
            "M1"                           # format code + leg count
            f"{name.ljust(20)[:20]}"       # passenger name
            f"E"                           # E ticket indicator
            f"{pnr.ljust(7)}"              # PNR
            f"{dep}{arr}"                  # FROM / TO
            f"{self.airline} "             # operating carrier
            f"{flight.rjust(5)}"           # flight number
            f"{self._julian(dep_date)}"    # Julian dep date
            f"Y"                           # compartment
            f"{seat.ljust(4)}"             # seat
            f"{str(seq).zfill(5)}"         # check-in sequence no.
            f"1"                           # pax status (1 = boarded)
        )

        # Conditional items — airline-loyalty tier, FF number,
        # selectee indicator for TSA Secure Flight, ID document number
        conditional = self._build_conditional(
            ff_number=ff_number,
            tsa_prechk_eligible=tsa_prechk_eligible,
            global_entry_known=global_entry_known,
        )

        # Signed trailer.  Version 8 BCBP appends "Signature (De)" —
        # RSA-1024 / -2048 over a defined canonicalization of the
        # pass. Receivers (TSA scanners, CBP gates, CUSS kiosks)
        # verify against the airline's IATA-published pubkey.
        to_sign = (mandatory + conditional).encode("ascii")
        sig_b64 = sign_bcbp_conditional(to_sign, self.signing_key_pem)
        return mandatory + conditional + f">2180{sig_b64}"


def verify_at_gate(bcbp: str, iata_pubkey_pem: bytes) -> dict:
    """Invoked by gate reader / TSA CAT-II scanner at boarding."""
    ok, decoded = verify_bcbp_conditional(bcbp.encode(), iata_pubkey_pem)
    if not ok:
        raise RuntimeError("BCBP signature invalid or tampered")
    return decoded


# ---- Failure mode ----
#
# Before BCBP Version 8 and signed boarding passes, anyone could alter
# boarding pass data trivially (the infamous "boardingpass.com forgery"
# line of research by Bruce Schneier and others, circa 2007). Signing
# plugged that hole: TSA Secure Flight + CBP Global Entry checkpoints
# re-verify the RSA signature before letting the passenger through the
# sterile-corridor door or the trusted-traveler lane.
#
# An RSA factoring attack on any airline's BCBP signing key lets an
# attacker mint boarding passes under that carrier's identity — bypass
# TSA PreCheck/CLEAR risk-based lane routing, print a pass for a
# no-ID passenger, impersonate crew passes where those use the same
# format family.  The IATA BCBP pubkey registry is one signing key per
# carrier, ~300 carriers total, and the key rotation cadence is
# measured in years.
