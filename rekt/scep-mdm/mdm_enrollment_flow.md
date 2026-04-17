# SCEP-in-MDM — how `scep_enrollment.go` is actually exercised

SCEP (Simple Certificate Enrollment Protocol, RFC 8894) is the
ubiquitous wire protocol by which every major MDM platform issues
per-device RSA client certs to enrolled iOS / iPadOS / macOS /
Android Enterprise / Windows MDM fleets.  The SCEP messages are
PKCS#7-wrapped PKCS#10 CSRs, signed and encrypted with RSA the
whole way through.

## Consumers

- **Jamf Pro / Jamf School** — iOS/macOS fleet cert issuance via the
  "SCEP Proxy" built into Jamf, hitting Microsoft ADCS NDES or
  SCEPman on the back end.
- **Microsoft Intune** — "SCEP certificate profile" policies target
  user + device scopes; Intune Connector for Active Directory
  forwards requests to NDES.
- **VMware Workspace ONE UEM** — "Certificate Authority" integration
  points to EJBCA or Microsoft CA via SCEP.
- **Kandji, Mosyle, Hexnode, IBM MaaS360, SOTI MobiControl** — all
  ship SCEP profile payloads.
- **Cisco Meraki Systems Manager** — SCEP profile for 802.1X client
  certs on managed Macs and iPads.
- **Apple Configurator 2 / Apple Business Manager** — supervised
  device enrollment emits a SCEP payload during ADE.

## End-to-end flow (what `scep_enrollment.go` plugs into)

1. MDM server pushes a `com.apple.security.scep` (or equivalent)
   Configuration Profile to the device.  Profile carries the CA
   fingerprint, SCEP URL, challenge password, key-usage flags.
2. Device generates an RSA-2048 keypair in the Secure Enclave /
   StrongBox / TPM.
3. Device builds a PKCS#10 CSR + a PKCS#7 SignedData envelope
   ("PKIMessage"), signs it with the CSR key (or a self-signed
   enrollment cert), encrypts with the SCEP CA's RSA pubkey.
4. `GET /scep?operation=PKIOperation&message=...` → CA.
5. CA (NDES / EJBCA / SCEPman / certnanny) decrypts with its RSA key,
   verifies the inner signature, validates the challenge, issues
   the device cert, wraps the response in a signed+encrypted
   `CertRep` PKIMessage.
6. Device installs the cert into its keychain; every subsequent
   802.1X / VPN / WPA2-Enterprise / Wi-Fi handshake uses it.

## Where it lands in downstream auth

- 802.1X EAP-TLS on corporate Wi-Fi and wired LANs (see
  `eap-tls-wifi/`).
- Always-On VPN (iOS Per-App VPN, macOS NEVPN) uses the same cert
  for IKEv2 authentication (see `ipsec-ikev2-libreswan/`).
- Microsoft Entra / Azure AD "certificate-based auth" maps this
  device cert to a conditional-access device-trust signal.
- Smart-card-equivalent login on managed workstations.

## Threat model under RSA factoring break

Two distinct failure modes:

1. **CA key factored.**  Attacker mints arbitrary device-legit-
   looking client certs.  Walks onto corporate Wi-Fi, establishes
   a Per-App VPN tunnel, presents a "device-trust" signal to Entra,
   and satisfies conditional-access device compliance checks
   without touching a real MDM-enrolled endpoint.

2. **Individual device key factored** (RSA-2048 cert exposed via a
   weak-random Secure Enclave bug or leaked from an old iOS
   profile).  Attacker pins that device as their own, defeating
   device-bound MFA and Zero-Trust posture checks for that user's
   whole managed fleet.

Rotation requires re-enrolling every device; at a 100k-endpoint
enterprise that's a multi-week coordinated rollout with guaranteed
breakage windows.
