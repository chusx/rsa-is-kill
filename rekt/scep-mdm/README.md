# scep-mdm — RSA-only certificate enrollment for MDM

**Software:** micromdm/scep (and NDES / Cisco ISE / Jamf Pro internally) 
**Industry:** Enterprise mobile device management, network access control 
**Algorithm:** RSA-2048 (all SCEP operations: signing, encryption, certificate issuance) 

## What it does

SCEP (Simple Certificate Enrollment Protocol) is how enterprise MDM systems
automatically issue certificates to managed devices. It's the enrollment backbone
that puts the device certificate on your laptop when it joins Intune or Jamf.

SCEP is used by:
- **Apple MDM** — Intune, Jamf, Mosyle, Kandji all use SCEP to issue Wi-Fi certs,
 VPN certs, and email certs to iOS and macOS devices
- **Microsoft NDES** (Network Device Enrollment Service) — the Windows Server
 SCEP implementation, deployed in most enterprise environments
- **Cisco ISE** — SCEP for endpoint VPN certificate enrollment
- **Aruba ClearPass** — SCEP for NAC device certificate issuance
- **Network equipment** — Cisco IOS, Juniper JunOS, Aruba APs use SCEP to get
 their management certificates from enterprise CAs

The SCEP protocol flow is RSA end-to-end:
1. Device generates an RSA-2048 keypair and signs a PKCS#10 CSR
2. CSR is encrypted to the CA's RSA public key (PKCS#7 EnvelopedData)
3. That is signed with the device's RSA key (PKCS#7 SignedData)
4. CA decrypts with its RSA private key, issues the certificate
5. Certificate is encrypted back to the device's RSA key

RFC 8894 (2020) standardizes SCEP. It does not define any non-RSA algorithm.
There is no SCEP v3 draft with non-RSA support. The IETF has no active SCEP/non-RSA work item.

## Why it's stuck

- SCEP protocol has no algorithm negotiation — client and server must agree on RSA.
 The entire PKIMessage format is PKCS#7, which predates non-RSA
- NDES (the dominant enterprise SCEP server) is a Windows Server component.
 Windows Server has no non-RSA SCEP support and no announced roadmap
- Apple MDM configuration profiles specify SCEP with `KeySize` (always RSA-2048).
 The MDM profile schema has no non-RSA key type
- Every MDM-enrolled device (iOS, macOS, Windows, Android in enterprise MDM)
 uses RSA-2048 certificates issued via SCEP for Wi-Fi, VPN, and S/MIME

## impact

SCEP is the factory that produces all the device certificates used for enterprise
Wi-Fi (EAP-TLS), VPN, and email. the CA's RSA key is the key to that factory.

- factor the NDES CA RSA-2048 key and you can issue certificates for any device
 to any CN. forge a device certificate for the CEO's laptop, a server certificate
 for a production system, a VPN certificate for anyone in the directory
- SCEP enrollment requests are encrypted to the CA's RSA public key. HNDL-captured
 enrollment traffic contains all the device CSRs ever submitted. retroactively
 decrypt every enrollment and you have every device's private key (from the CSR
 context) and identity
- Cisco ISE uses SCEP-issued certs for NAC posture assessment. forge valid device
 certs for any endpoint and pass NAC checks to get onto the corporate network
 without MDM enrollment, compliance checks, or any of the usual gatekeeping
- Apple MDM uses SCEP-issued push certificates for device management commands.
 forge the certificate and you can send MDM commands (wipe, lock, install app)
 to any enrolled device in the MDM

## Code

`scep_enrollment.go` — `GenerateKeyAndCSR()` (RSA-2048 keypair + PKCS#10 CSR),
`PKCSReq()` (PKCS#7 envelope: CSR encrypted to CA RSA key, signed with device RSA key),
and `HandlePKCSReq()` (CA side: RSA decrypt, issue certificate).
