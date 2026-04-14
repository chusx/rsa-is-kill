# eap-tls-wifi — RSA certificates for enterprise Wi-Fi (802.1X)

**Software:** FreeRADIUS (FreeRADIUS/freeradius-server)  
**Industry:** Enterprise Wi-Fi, hospital networks, university networks, airport Wi-Fi  
**Algorithm:** RSA-2048 (client and server certificates, TLS handshake)  
**PQC migration plan:** None — EAP-TLS (RFC 5216 / RFC 9190) has no PQC cipher suite; no RADIUS server supports PQC

## What it does

WPA2-Enterprise and WPA3-Enterprise use 802.1X network access control with
EAP-TLS for mutual certificate-based authentication. Every device connecting
to an enterprise Wi-Fi network presents an RSA-2048 certificate to the RADIUS
server (FreeRADIUS, Cisco ISE, Aruba ClearPass, Microsoft NPS).

Scale:
- **Eduroam**: ~10,000 universities globally, 800M+ authentications/year
- **Cisco ISE**: 100M+ managed endpoints
- **Enterprise deployments**: every Fortune 500 company
- **Healthcare**: hospital device authentication (medical devices, workstations)
- **Wi-Fi calling (VoWi-Fi)**: IMS authentication over 802.1X in hotels/airports

## Why it's stuck

The entire 802.1X ecosystem must upgrade simultaneously:
1. RADIUS server (FreeRADIUS, ISE, ClearPass) — no PQC TLS cipher suite support
2. Supplicant (Windows `wpa_supplicant`, iOS Wi-Fi, Android) — no PQC cert support
3. Enterprise PKI (ADCS, EJBCA, Vault PKI) — no PQC certificate issuance
4. MDM enrollment (Intune, JAMF) — no PQC SCEP/ACME certificate delivery
5. AP / Switch 802.1X enforcement — firmware updates

No single vendor can move without the others. This is the flag day problem
for enterprise networking. A CRQC forging device certificates allows connecting
any device to any secured corporate Wi-Fi network.

## impact

EAP-TLS is the gatekeeper to enterprise networks. the certificate is the credential. forge the certificate and you walk right in, with no failed auth logs, no anomalies, nothing in the SIEM.

- forge any device certificate and connect to enterprise Wi-Fi without credentials, MDM enrollment, or physical device access. the 802.1X authenticator sees a valid cert and waves you through
- hospital networks: forge a nurse workstation certificate, get onto the EHR VLAN and the medical device VLAN
- eduroam covers about 10,000 universities in a single global trust federation. forge an institution's RADIUS server certificate and harvest credentials from roaming students connecting from every other member institution
- many OT networks use 802.1X on wired Ethernet ports. forge a certificate, plug in anywhere, get an authorized IP, and pivot to the SCADA network from there
## Code

`freeradius_eap_tls.c` — `tls_session_new()` showing `SSL_VERIFY_PEER` for
mutual TLS and RSA cipher suite configuration, with the 802.1X deployment
scale analysis.
