"""
Factor the Hubject V2G Root CA RSA-2048 key, forge contract certificates for
any EV, and charge arbitrary vehicles against arbitrary accounts across the
entire European Plug-and-Charge roaming network.
"""

import sys, hashlib, json, time
import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from poly_factor import PolynomialFactorer

# ISO 15118-2 message types
MSG_SESSION_SETUP     = "SessionSetupReq"
MSG_AUTHORIZATION     = "AuthorizationReq"
MSG_CERT_INSTALL      = "CertificateInstallationReq"
MSG_CHARGE_PARAMETER  = "ChargeParameterDiscoveryReq"
MSG_METERING_RECEIPT  = "MeteringReceiptReq"


def extract_v2g_root(charger_tls_cert: str) -> bytes:
    """Extract the V2G Root CA cert from an EV charger's TLS chain.
    Hubject is the dominant V2G Root operator."""
    print(f"    charger cert: {charger_tls_cert}")
    print("    V2G Root CA: Hubject OCA (RSA-2048)")
    return b"-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----\n"


def factor_v2g_root(cert_pem: bytes) -> bytes:
    factorer = PolynomialFactorer()
    return factorer.privkey_from_cert_pem(cert_pem)


def forge_contract_cert(v2g_root_privkey: bytes, vin: str,
                         emaid: str) -> bytes:
    """Issue a forged contract certificate binding a VIN to a mobility account.
    ISO 15118-2 CertificateInstallationRes delivers this."""
    print(f"    VIN: {vin}")
    print(f"    EMAID: {emaid}")
    return b"FORGED_CONTRACT_CERT"


def authorize_charging(contract_cert: bytes, contract_key: bytes,
                        secc_challenge: bytes) -> bytes:
    """Sign the AuthorizationReq with the forged contract cert.
    PSS signature over GenChallenge per ISO 15118-2."""
    sig = b"\x00" * 256
    print("    AuthorizationReq: PSS signature over GenChallenge")
    return sig


def forge_metering_receipt(energy_kwh: float, price_eur: float,
                            receipt_key: bytes) -> dict:
    """Forge a signed metering receipt (German Eichrecht compliance)."""
    return {
        "energy_kwh": energy_kwh,
        "price_eur": price_eur,
        "timestamp": int(time.time()),
        "signature": "RSA-2048 (Eichrecht sealed meter)",
    }


if __name__ == "__main__":
    print("[*] ISO 15118 Plug-and-Charge / V2G PKI attack")
    print("[1] extracting Hubject V2G Root CA from charger TLS chain")
    cert = extract_v2g_root("charger_alpitronic_hpc.pem")
    print("    de-facto roaming fabric for 30+ countries")

    print("[2] factoring Hubject V2G Root CA RSA-2048")
    factorer = PolynomialFactorer()
    print("    p, q recovered — V2G Root CA key derived")

    print("[3] forging contract certificate")
    contract = forge_contract_cert(
        b"V2G_ROOT_PRIVKEY",
        vin="WBA1234567890XXXX",
        emaid="DE-ABC-C12345678-N",
    )
    print("    contract cert: VW vehicle charged to arbitrary Ionity account")

    print("[4] Plug-and-Charge authentication at charger")
    sig = authorize_charging(contract, b"CONTRACT_KEY", b"\xAB" * 16)
    print("    SECC verifies contract cert chain -> V2G Root -> PASS")
    print("    charging session authorized")

    print("[5] charging at victim's expense")
    print("    50 kWh @ 0.59 EUR/kWh = 29.50 EUR billed to victim EMAID")
    print("    charger cannot distinguish forged from legitimate contract cert")

    print("[6] forging Eichrecht metering receipt")
    receipt = forge_metering_receipt(50.0, 29.50, b"METER_KEY")
    print(f"    signed receipt: {receipt['energy_kwh']} kWh, EUR {receipt['price_eur']}")
    print("    consumer protection evidentiary chain collapses")

    print("[7] impact:")
    print("    - V2G PKI: millions of certs issued by Hubject alone")
    print("    - every EU EV from ~2019 supports ISO 15118-2 (RSA)")
    print("    - AFIR 2023/1804: crypto standards referenced in EU law")
    print("    - ~4M public chargers globally (2026); 15M projected by 2030")
    print("    - ISO 15118-2 vehicles on road for 15+ years demand RSA back-compat")
    print("[*] Hubject V2G Root rotation touches every EV, every charger, every contract")
