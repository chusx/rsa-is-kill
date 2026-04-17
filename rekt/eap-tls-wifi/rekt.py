"""
Factor the enterprise RADIUS server's RSA-2048 TLS cert, forge device
certificates matching any MDM-enrolled endpoint, and connect to any
WPA2/WPA3-Enterprise Wi-Fi network with no credentials and no SIEM alert.
"""

import sys, hashlib
sys.path.insert(0, "../..")
from poly_factor import PolynomialFactorer

# 802.1X / EAP-TLS flow
EAP_TYPE_TLS = 13
RADIUS_ACCESS_REQUEST  = 1
RADIUS_ACCESS_ACCEPT   = 2


def extract_radius_cert(ssid: str, interface: str = "wlan0") -> bytes:
    """Extract the RADIUS server's RSA-2048 cert from an EAP-TLS handshake.
    Sent in EAP-TLS ServerHello during 802.1X authentication."""
    print(f"    SSID: {ssid}")
    print(f"    EAP-TLS handshake on {interface}")
    print("    RADIUS server cert: RSA-2048 (FreeRADIUS / Cisco ISE)")
    return b"-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----\n"


def factor_radius_cert(cert_pem: bytes) -> bytes:
    factorer = PolynomialFactorer()
    return factorer.privkey_from_cert_pem(cert_pem)


def forge_device_cert(ca_privkey: bytes, device_cn: str, ou: str) -> bytes:
    """Issue a forged device certificate matching the enterprise PKI template.
    MDM (Intune/JAMF) issues these via SCEP; we skip the MDM."""
    print(f"    CN: {device_cn}")
    print(f"    OU: {ou}")
    print("    EKU: clientAuth (1.3.6.1.5.5.7.3.2)")
    return b"FORGED_DEVICE_CERT"


def eap_tls_authenticate(ssid: str, device_cert: bytes, device_key: bytes):
    """Perform EAP-TLS mutual authentication with the forged cert."""
    print(f"    802.1X EAPOL-Start on SSID '{ssid}'")
    print("    EAP-TLS: ClientHello + forged device cert")
    print("    RADIUS server verifies cert chain -> enterprise CA -> PASS")
    print("    EAP-Success -> EAPOL-Key -> WPA2/WPA3 4-way handshake")
    print("    connected to enterprise network")


def harvest_eduroam_credentials(institution_cert: bytes, forged_key: bytes):
    """Impersonate an eduroam RADIUS server to harvest roaming credentials.
    ~10,000 universities in a single global trust federation."""
    print("    spoofing eduroam RADIUS server with forged cert")
    print("    roaming students connect from any member institution")
    print("    EAP-TTLS/PAP inner auth: credentials captured in cleartext")


if __name__ == "__main__":
    print("[*] EAP-TLS / 802.1X enterprise Wi-Fi attack")
    ssid = "CorpSecure"

    print(f"[1] extracting RADIUS server cert from EAP-TLS handshake")
    cert = extract_radius_cert(ssid)
    print("    server: Cisco ISE, cert issued by enterprise ADCS")

    print("[2] factoring RADIUS RSA-2048 cert")
    factorer = PolynomialFactorer()
    print("    p, q recovered — enterprise Wi-Fi CA key derived")

    print("[3] forging device certificate")
    device_cert = forge_device_cert(
        b"CA_PRIVKEY",
        device_cn="DESKTOP-FRGD001.corp.example.com",
        ou="IT Department",
    )
    print("    matches enterprise SCEP template from Intune/JAMF")

    print("[4] EAP-TLS authentication with forged cert")
    eap_tls_authenticate(ssid, device_cert, b"FORGED_KEY")
    print("    no failed auth logs — cert is valid")
    print("    no SIEM anomaly — looks like normal device enrollment")

    print("[5] eduroam credential harvesting")
    harvest_eduroam_credentials(b"FORGED_RADIUS_CERT", b"KEY")
    print("    ~800M authentications/year across 10k universities")

    print("[6] additional attack surfaces:")
    print("    - hospital EHR VLAN: forge nurse workstation cert")
    print("    - OT networks with 802.1X on wired Ethernet ports")
    print("    - Wi-Fi calling (VoWi-Fi): IMS auth over 802.1X")
    print("    - all 5 components must upgrade simultaneously (flag day problem):")
    print("      RADIUS server, supplicant, PKI, MDM, AP firmware")
    print("[*] Cisco ISE: 100M+ managed endpoints; Fortune 500 everywhere")
