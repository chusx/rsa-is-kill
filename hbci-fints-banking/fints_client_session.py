"""
fints_client_session.py

HBCI / FinTS 3.0 client session — the German-banking online-banking
protocol used by every Sparkasse, Volksbank, Deutsche Bank, Commerzbank,
DKB, ING-DiBa, Postbank customer through personal-finance clients like
StarMoney, WISO Mein Geld, Hibiscus, MoneyMoney, Subsembly Banking4, and
the server side of Hypovereinsbank's own HBCI gateway.

This orchestrates sign / encrypt / verify / decrypt of FinTS message
segments on top of the RSA/RDH-10 security profile primitives in
`hbci_rsa_auth.py`.

Context: FinTS volume is on the order of tens of millions of
transactions/day across German retail banking. HBCI containers are
signed under each customer's RSA key (softkey file .key/.kye, or
SECCOS smartcard — a SIZ-issued chipcard with on-card RSA).
"""

import os
import random
from datetime import datetime
from hbci_rsa_auth import (
    fints_sign_segment,      # PKCS#1 v1.5 sign under customer RSA priv
    fints_verify_segment,    # verify under bank RSA pubkey
    fints_encrypt_session,   # RSA-key-agreement → 2-key-3DES bulk
    fints_decrypt_session,
)


class FinTSSession:
    def __init__(self, blz: str, user_id: str, url: str,
                  rsa_key_store):
        self.blz      = blz          # Bankleitzahl (8-digit German BLZ)
        self.user_id  = user_id      # Kundennummer
        self.url      = url          # PIN/TAN endpoint or HBCI+ endpoint
        self.key_store = rsa_key_store
        self.tan_method = None
        self.dialog_id  = "0"        # assigned by bank on first response
        self.msg_ref    = 1

    # ---- Dialog init: synchronization + key check ----
    def synchronize(self):
        req = [
            self._seg_header("HNHBK", 1, 3),          # message header
            self._seg_signature_head(2),              # HNSHK signature header
            self._seg_encryption_head(3),             # HNVSK encryption header
            self._seg_encryption_data(4,              # HNVSD payload
                [
                    self._seg_dialog_init(5),         # HKIDN identification
                    self._seg_processing_prep(6),     # HKVVB processing prep
                    self._seg_sync(7),                # HKSYN sync request
                ]),
            self._seg_signature_tail(8),              # HNSHA signature tail
            self._seg_msg_tail(9),                    # HNHBS
        ]
        raw = self._assemble(req)
        signed = fints_sign_segment(raw, self.key_store.signing_key)
        wire   = fints_encrypt_session(signed, self.key_store.bank_enc_pubkey)
        resp   = self._post(wire)
        plain  = fints_decrypt_session(resp, self.key_store.signing_key)
        fints_verify_segment(plain, self.key_store.bank_sig_pubkey)
        self._apply_response(plain)

    # ---- SEPA credit transfer (HKCCS) ----
    def send_sepa_transfer(self, iban_debit, iban_credit, amount_eur,
                             purpose: str, tan: str):
        hkccs = self._seg_hkccs(5, iban_debit, iban_credit,
                                 amount_eur, purpose)
        htan  = self._seg_htan(6, tan)
        req = [
            self._seg_header("HNHBK", 1, 3),
            self._seg_signature_head(2),
            self._seg_encryption_head(3),
            self._seg_encryption_data(4, [hkccs, htan]),
            self._seg_signature_tail(7),
            self._seg_msg_tail(8),
        ]
        raw = self._assemble(req)
        signed = fints_sign_segment(raw, self.key_store.signing_key)
        wire   = fints_encrypt_session(signed, self.key_store.bank_enc_pubkey)
        resp   = self._post(wire)
        plain  = fints_decrypt_session(resp, self.key_store.signing_key)
        fints_verify_segment(plain, self.key_store.bank_sig_pubkey)
        return self._parse_booking_status(plain)

    # ---- helpers (schematic) ----
    def _seg_header(self, *a):            ...
    def _seg_signature_head(self, ref):   ...
    def _seg_signature_tail(self, ref):   ...
    def _seg_encryption_head(self, ref):  ...
    def _seg_encryption_data(self, ref, inner): ...
    def _seg_msg_tail(self, ref):         ...
    def _seg_dialog_init(self, ref):      ...
    def _seg_processing_prep(self, ref):  ...
    def _seg_sync(self, ref):             ...
    def _seg_hkccs(self, ref, *a):        ...
    def _seg_htan(self, ref, tan):        ...
    def _assemble(self, segs):            ...
    def _post(self, wire):                ...
    def _apply_response(self, plain):     ...
    def _parse_booking_status(self, plain): ...


# Breakage:
#
# FinTS RDH-10 relies on per-customer RSA-2048 signing + bank-side
# RSA-2048 encryption pubkeys, both anchored via the Zentraler Kreditausschuss
# / Deutsche Kreditwirtschaft trust framework (DK CA). A factoring
# break lets an attacker:
#   - Forge signed HKCCS SEPA transfers on behalf of any customer
#     whose softkey file or card has been observed online exactly
#     once (public key sufficient to forge signatures under a broken
#     RSA).
#   - Decrypt captured HBCI session traffic offline — every historic
#     statement, balance, recipient IBAN.
# Germany's online banking plant would need an emergency flip to
# PSD2 PIN/TAN-only (no signed-message HBCI) while a non-RSA profile
# is standardized.
