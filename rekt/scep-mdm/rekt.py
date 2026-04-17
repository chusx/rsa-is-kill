"""
Factor the SCEP CA's RSA-2048 key to issue device certificates for any
endpoint. Bypass NAC, enroll rogue devices in MDM, and retroactively decrypt
captured SCEP enrollment traffic. RFC 8894 defines no non-RSA algorithm.
"""
import sys
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

import hashlib
import os

# SCEP message types (RFC 8894)
SCEP_PKCS_REQ = 19        # PKCSReq — enrollment request
SCEP_CERT_REP = 3         # CertRep — CA response
SCEP_GET_CA_CERT = 0      # GetCACert — fetch CA cert (unauthenticated)

# MDM platforms using SCEP
MDM_PLATFORMS = ["Microsoft Intune/NDES", "Jamf Pro", "Mosyle",
                 "Kandji", "Cisco ISE", "Aruba ClearPass"]


def fetch_scep_ca_cert(scep_url: str) -> bytes:
    """Fetch the SCEP CA certificate — unauthenticated HTTP GET.

    GET /certsrv/mscep/mscep.dll/pkiclient.exe?operation=GetCACert
    No credentials required. This is the RSA-2048 key we need.
    """
    print(f"[*] GET {scep_url}?operation=GetCACert")
    print("[*] CA certificate retrieved (RSA-2048, no auth required)")
    return b"-----BEGIN CERTIFICATE-----\n...(SCEP CA PEM)...\n-----END CERTIFICATE-----\n"


def forge_device_cert(factorer: PolynomialFactorer,
                      ca_cert_pem: bytes,
                      device_cn: str, device_type: str = "laptop") -> bytes:
    """Forge a device certificate for any CN.

    SCEP-issued certs are used for EAP-TLS (Wi-Fi), VPN, and S/MIME.
    The CN typically maps to a device ID or username.
    """
    priv = factorer.privkey_from_cert_pem(ca_cert_pem)
    print(f"[*] forged device cert: CN={device_cn} (type={device_type})")
    print("[*] valid for: EAP-TLS Wi-Fi, VPN, email S/MIME")
    return priv


def bypass_nac(factorer: PolynomialFactorer,
               ca_cert_pem: bytes, radius_server: str):
    """Bypass 802.1X / NAC with a forged device certificate.

    Cisco ISE / Aruba ClearPass use SCEP-issued certs for EAP-TLS
    endpoint authentication. Forge the cert -> pass NAC -> get on
    the corporate network without MDM enrollment or compliance checks.
    """
    print(f"[*] forging cert for NAC bypass at {radius_server}")
    priv = factorer.privkey_from_cert_pem(ca_cert_pem)
    print("[*] EAP-TLS handshake with RADIUS server...")
    print("[*] 802.1X authentication: PASS")
    print("[*] on corporate network without MDM, without compliance check")
    return priv


def decrypt_captured_scep_enrollment(factorer: PolynomialFactorer,
                                     ca_cert_pem: bytes,
                                     captured_pkcsreq: bytes) -> bytes:
    """Retroactively decrypt captured SCEP enrollment traffic.

    SCEP PKCSReq messages encrypt the CSR to the CA's RSA public key.
    HNDL-captured enrollment traffic contains every device's CSR.
    Factor the CA key -> decrypt all enrollments -> recover device identities.
    """
    print("[*] decrypting captured SCEP PKCSReq (PKCS#7 EnvelopedData)...")
    plaintext = factorer.decrypt_rsa_oaep(ca_cert_pem, captured_pkcsreq)
    print("[*] CSR recovered — device identity and key material exposed")
    return plaintext


def send_mdm_wipe_command(device_id: str):
    """Send MDM commands using a forged push certificate."""
    print(f"[*] sending RemoteWipe to device {device_id}")
    print("[*] MDM command accepted — device data erased")


if __name__ == "__main__":
    f = PolynomialFactorer()

    print("=== SCEP MDM — device certificate forgery (RFC 8894) ===")
    print(f"    MDM platforms: {', '.join(MDM_PLATFORMS[:3])}, ...")
    print("    RFC 8894 (2020): zero non-RSA algorithms defined")
    print()

    print("[1] fetching SCEP CA cert (unauthenticated HTTP GET)...")
    ca_cert = fetch_scep_ca_cert("https://ndes.corp.example.com/certsrv/mscep")

    print("[2] factoring SCEP CA RSA-2048 key...")

    print("[3] forging device cert: CEO's laptop...")
    forge_device_cert(f, ca_cert, "CEO-LAPTOP-001", "laptop")

    print("[4] bypassing 802.1X NAC with forged cert...")
    bypass_nac(f, ca_cert, "radius.corp.example.com")

    print("[5] decrypting captured SCEP enrollment traffic (HNDL)...")
    print("    every device CSR ever submitted -> identity + key material")

    print("[6] sending MDM wipe command via forged push cert...")
    send_mdm_wipe_command("iPhone-CFO-002")

    print()
    print("[*] Apple MDM profile: KeySize = 2048 (RSA), no alternatives")
    print("[*] SCEP protocol has no algorithm negotiation")
    print("[*] IETF has no active SCEP/non-RSA work item")
