"""
pi_interface_auth_flow.py

OSIsoft / AVEVA PI System — PI Interface (data collector, formerly
UniInt) authentication flow into a PI Data Archive. Runs on every
process-historian deployment in industry: oil refineries, power
generation fleets, pulp-and-paper, pharma, food & beverage, water
utilities. Nearly every Fortune 500 industrial operator owns a
PI System.

The AF SDK / PI SDK TLS handshake uses WIS (Windows Integrated
Security) Kerberos by default, but PI System's own "PI Trust" / PI
Mapping authentication uses an RSA-based challenge-response tied to
the PI Archive's certificate (or the archive's WIS domain account
cert in AD). The RSA primitives are in `osisoft_pi_rsa.py`.

This file is the PI Interface bringup — the logic that runs inside
PI-OPCUA, PI-Ping, PI-Modbus, PI-Mirror, PIConnector Rockwell/
Siemens, etc., on every historian-collector node worldwide.
"""

from datetime import datetime, timedelta
from osisoft_pi_rsa import (
    sign_pi_challenge_rsa,
    verify_archive_cert_chain,
    enroll_interface_with_archive,
)


class PIInterfaceClient:
    """
    Represents a running PI Interface node (UniInt) streaming tags
    into a PI Data Archive node.
    """
    def __init__(self, archive_endpoint: str, interface_id: str,
                  trust_store_pem: bytes, private_key_pem: bytes):
        self.archive_endpoint  = archive_endpoint    # e.g. PISRV01:5450
        self.interface_id      = interface_id        # SMT-assigned ID
        self.trust_store       = trust_store_pem     # corporate Issuing CA
        self.private_key       = private_key_pem     # RSA-2048 priv
        self.session           = None

    def authenticate(self) -> dict:
        """
        The PI authentication handshake:
        1. TCP connect to archive listener
        2. Receive archive's cert chain + random challenge
        3. Verify cert chain under enterprise PKI
        4. Sign challenge with interface RSA private key
        5. Archive verifies sig, issues PI session token
        """
        tcp = _pi_connect(self.archive_endpoint)

        # 2. Archive sends a PIMessage containing its leaf cert
        # (issued by enterprise CA), an intermediate, and a 32-byte
        # nonce.
        archive_msg = tcp.recv_pi_message()
        archive_cert_chain = archive_msg["server_cert_chain"]
        nonce              = archive_msg["server_nonce"]

        # 3. Verify the cert chain.  Real deployments pin the
        # corporate Issuing CA here; the PI System ships with an
        # OSIsoft-operated default trust store that most large
        # installs replace at go-live.
        if not verify_archive_cert_chain(archive_cert_chain,
                                           self.trust_store):
            raise RuntimeError("archive cert chain verify failed")

        # 4. Sign the challenge using the interface's RSA key. The
        # to-sign construction is "PI-AUTH-v2 || interface_id ||
        # nonce || utc_now" per OSIsoft PI System Security
        # Audit Tools docs.
        utc = datetime.utcnow().isoformat() + "Z"
        to_sign = b"PI-AUTH-v2|" + self.interface_id.encode() + \
                   b"|" + nonce + b"|" + utc.encode()
        sig = sign_pi_challenge_rsa(to_sign, self.private_key)

        # 5. Send auth response
        tcp.send_pi_message({
            "op":             "AUTH",
            "interface_id":   self.interface_id,
            "timestamp":      utc,
            "signature_b64":  sig.hex(),
        })
        reply = tcp.recv_pi_message()
        if reply["status"] != "OK":
            raise RuntimeError(f"auth failed: {reply.get('reason')}")

        self.session = {
            "token":   reply["session_token"],
            "expires": datetime.utcnow() + timedelta(hours=8),
            "tcp":     tcp,
        }
        return self.session

    def stream_snapshot(self, tag_updates: list[tuple[str, float, datetime]]):
        """
        After auth, flush a batch of (tag, value, timestamp) updates.
        Volume is typically 100k-1M updates/sec on big refinery
        historians.
        """
        self.session["tcp"].send_pi_message({
            "op":       "SNAPSHOT_POST",
            "token":    self.session["token"],
            "updates":  tag_updates,
        })


def _pi_connect(endpoint: str):
    ...


# ---- Breakage ----
#
# A factoring attack on the enterprise CA that signs PI Archive and
# PI Interface certs lets an attacker:
#   - Impersonate an archive and accept data from legitimate
#     interfaces — an attacker-controlled historian receives the
#     operational process stream and can use it for industrial
#     espionage / sabotage planning.
#   - Impersonate an interface and push *forged* tag values into the
#     archive — "normal" readings while the process is actually
#     drifting dangerously, hiding evidence of sabotage or
#     malfunction from operators and regulators.
# The PI System is typically the system of record for plant
# operation; most US utility ISO filings, pharma batch records, and
# oil-pipeline SCADA logs ultimately rest on PI data integrity.
