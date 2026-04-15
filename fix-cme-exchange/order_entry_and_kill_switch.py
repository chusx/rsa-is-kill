"""
order_entry_and_kill_switch.py

Broker-dealer order-entry gateway: member firm sends FIX New Order
Single messages to CME iLink 3 / Nasdaq OUCH-ITCH (FIX wrapper) /
LSEG Millennium, and handles the SEC Rule 15c3-5 kill-switch
channel from the broker's risk desk.

This is the production gateway on the member-firm side. Co-located
in the exchange facility; ultra-low-latency C++ for the hot path in
real deployments — Python here to keep the structural logic
readable. RSA-signing happens on a sidecar HSM (nShield, Luna, YubiHSM)
rather than in the critical path for every order.
"""

from __future__ import annotations
import hashlib
import ssl
import socket
import time
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

EXCHANGE_MEMBER_CA_PATH = "/pki/exchange-member-root.pem"
BROKER_RISK_ROOT_PATH   = "/pki/broker-risk-root.pem"
MEMBER_SESSION_CERT     = "/pki/member-leaf.crt"
MEMBER_SESSION_KEY      = "/pki/member-leaf.key"


# ---------------------------------------------------------------
# 1. FIX session: mutual TLS to the exchange order-entry gateway
# ---------------------------------------------------------------

def open_order_entry_session(host: str, port: int) -> ssl.SSLSocket:
    ctx = ssl.create_default_context(
        purpose=ssl.Purpose.SERVER_AUTH,
        cafile=EXCHANGE_MEMBER_CA_PATH,
    )
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    ctx.load_cert_chain(MEMBER_SESSION_CERT, MEMBER_SESSION_KEY)
    sock = socket.create_connection((host, port), timeout=5.0)
    tls  = ctx.wrap_socket(sock, server_hostname=host)
    fix_logon(tls)
    return tls


def fix_logon(tls: ssl.SSLSocket) -> None:
    # Tag 98=0 (NONE) at the FIX layer, because the underlying TLS
    # mutual-auth already authenticates the session. 141=Y reset
    # seqnum, 553/554 sender/target, 1137=9 FIX.5.0 SP2 Applied.
    body = (
        "35=A\x0149=MEMBER1\x0156=CME\x01"
        "34=1\x0198=0\x01108=30\x01141=Y\x01"
        "1137=9\x01"
    )
    tls.sendall(fix_wrap(body).encode())


def fix_wrap(body: str) -> str:
    raw = f"8=FIXT.1.1\x019={len(body)}\x01{body}"
    cs  = sum(raw.encode()) % 256
    return f"{raw}10={cs:03d}\x01"


# ---------------------------------------------------------------
# 2. iLink 3 per-message signing for risk-critical control msgs
# ---------------------------------------------------------------

@dataclass
class SignedControlMsg:
    msg_type: str                 # e.g. "CancelAll", "DisableInstrument"
    member_id: str
    issued_epoch: int
    seq: int
    body: bytes                   # FIX body bytes
    sig: bytes                    # RSA-PSS-SHA256 over body + header fields


def sign_control_message(body: bytes, seq: int, member_id: str,
                         signing_key: rsa.RSAPrivateKey) -> SignedControlMsg:
    issued = int(time.time())
    header = f"{member_id}|{issued}|{seq}|".encode()
    h = hashlib.sha256(header + body).digest()
    sig = signing_key.sign(
        h,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=32),
        hashes.Prehashed(hashes.SHA256()),
    )
    return SignedControlMsg(
        msg_type="Control",
        member_id=member_id,
        issued_epoch=issued,
        seq=seq,
        body=body,
        sig=sig,
    )


# ---------------------------------------------------------------
# 3. Kill-switch path — signed by the broker risk desk
#
#    SEC Rule 15c3-5 requires pre-trade risk controls. The risk
#    desk must be able to kill order flow from a mis-behaving algo
#    *faster than the algo can submit orders*. The kill command
#    arrives on a dedicated channel and is signed by the risk desk
#    HSM key; the order gateway verifies before acting.
# ---------------------------------------------------------------

@dataclass
class KillCommand:
    target_desk: str              # "US-EQ-ALGO-12"
    scope: str                    # "ALL" | "SYMBOL=AAPL" | "CLIENT=123"
    issued_epoch: int
    nonce: int
    sig: bytes


def verify_kill_command(cmd: KillCommand,
                        risk_desk_pub: rsa.RSAPublicKey,
                        last_seen_nonce: int) -> bool:
    if cmd.nonce <= last_seen_nonce:
        return False
    if abs(int(time.time()) - cmd.issued_epoch) > 5:
        # Max clock-skew tolerance on the risk link
        return False
    msg = (f"{cmd.target_desk}|{cmd.scope}|"
           f"{cmd.issued_epoch}|{cmd.nonce}").encode()
    h = hashlib.sha256(msg).digest()
    try:
        risk_desk_pub.verify(
            cmd.sig, h,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=32),
            hashes.Prehashed(hashes.SHA256()),
        )
        return True
    except Exception:
        return False


class OrderEntryGateway:
    def __init__(self, risk_pub: rsa.RSAPublicKey) -> None:
        self._risk_pub = risk_pub
        self._last_kill_nonce = 0
        self._killed_scopes: set[str] = set()

    def on_kill(self, cmd: KillCommand) -> None:
        if not verify_kill_command(cmd, self._risk_pub,
                                   self._last_kill_nonce):
            audit_log.warning("kill-cmd sig/nonce rejected: %s", cmd)
            return
        self._last_kill_nonce = cmd.nonce
        self._killed_scopes.add(cmd.scope)
        cancel_all_open_orders_matching(cmd.scope)
        audit_log.critical(
            "KILL EXECUTED scope=%s target=%s nonce=%d",
            cmd.scope, cmd.target_desk, cmd.nonce,
        )

    def on_new_order(self, fix_msg: bytes) -> None:
        if self._killed_scopes:
            # Policy: reject outright if any kill is in force that
            # intersects the order's scope.
            if order_intersects_kill(fix_msg, self._killed_scopes):
                reject_with_reason(fix_msg, "killswitch")
                return
        apply_pretrade_risk_checks(fix_msg)
        forward_to_exchange(fix_msg)


# ---------------------------------------------------------------
# 4. Regulatory-reporting submission (CAT, MiFID II RTS 27/28)
# ---------------------------------------------------------------

def sign_and_submit_cat_report(report_bytes: bytes,
                               firm_signing_key: rsa.RSAPrivateKey) -> None:
    """Member firm's CRD-bound signing key. CAT ingest verifies."""
    h = hashlib.sha256(report_bytes).digest()
    sig = firm_signing_key.sign(
        h,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=32),
        hashes.Prehashed(hashes.SHA256()),
    )
    submit_to_cat_ingest(report_bytes, sig)


# ---- Breakage ------------------------------------------------------
#
#   Exchange member-CA factored:
#     - Attacker mints member-firm client certs; submits signed
#       orders at industrial scale. Spoofing the book,
#       pre-announcement trading on factored-firm credentials,
#       layering across every venue of that CA.
#
#   Clearing-house root factored (DTCC / OCC / CME Clearing / LCH):
#     - Forged variation-margin calls, settlement instructions
#       redirected. Stressed-day settlement cascade — 2008-class
#       systemic event risk.
#
#   Broker 15c3-5 risk-desk signing key factored:
#     - Kill-switches ignored — or false kills inserted — during
#       a runaway-algo incident. Knight Capital (2012, $440M in
#       45 minutes) amplified because the brake pedal no longer
#       works.
#
#   CAT / MiFID II reporting CA factored:
#     - Historical regulatory-audit-trail integrity compromised.
#       Years of completed enforcement cases open to motion-to-
#       vacate on evidence-authenticity grounds.
