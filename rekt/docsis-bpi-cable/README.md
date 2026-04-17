# docsis-bpi-cable — RSA in every cable modem on the North American internet

**Standard:** CableLabs DOCSIS 3.0 / 3.1 / 4.0 Security Specification (BPI+)
**Industry:** Cable broadband — Comcast/Xfinity, Charter/Spectrum, Cox, Rogers, Vodafone
**Algorithm:** RSA-1024 (DOCSIS 3.0 legacy CMs), RSA-2048 (DOCSIS 3.1/4.0 modems, all current CMTS)

## What it does

Every cable modem (CM) you can buy at Best Buy or that your ISP ships you has a
factory-burned X.509 certificate issued under the CableLabs DOCSIS Root CA. When the
modem registers on a CMTS (Cable Modem Termination System at the headend), it goes
through BPI+ (Baseline Privacy Interface Plus) authentication:

1. Modem sends its DOCSIS certificate (RSA-1024 or RSA-2048) to the CMTS.
2. CMTS verifies the cert chains to CableLabs DOCSIS Root CA (hardcoded).
3. CMTS picks an AES Authorization Key (AK), encrypts to the modem's RSA public key
   via PKCS#1 v1.5 RSA-ENCRYPT, sends in BPKM Auth Reply.
4. Modem decrypts with its RSA private key, derives Traffic Encryption Keys (TEKs)
   for subsequent DOCSIS MAC-layer encryption.

The DOCSIS certificate chain:
- **CableLabs DOCSIS Root CA** (self-signed, RSA, valid until 2030s)
- **Manufacturer CA** (one per chipset vendor — Broadcom, Intel/MaxLinear, MediaTek)
- **Device Certificate** (per modem, factory-programmed into OTP or secure boot ROM)

There are >200 million cable modems in North America. Globally, cable broadband
subscribers are ~500 million. Every one authenticates via this RSA chain every time
it registers (every reboot, every service drop).

## Why it's stuck

- The DOCSIS Root CA cert is embedded in every CMTS vendor's firmware (Cisco cBR-8,
  Arris E6000, Casa Systems C100G, Harmonic CableOS) — a change requires coordinated
  firmware updates across every ISP's headend equipment.
- Modem device certificates are factory-programmed into the modem's OTP memory or
  burned into a secure boot ROM. They cannot be replaced without swapping the chip.
- DOCSIS 4.0 (published 2019, deployed 2024+) still mandates RSA. CableLabs has
  issued "BPI+ V2" drafts with ECDSA but no PQC work item exists.
- Modem replacement cycles are 5-10 years consumer-side, 15+ years for commercial.
  Comcast still has DOCSIS 3.0 modems with RSA-1024 certs in active deployment.
- CMTS software upgrades are change-managed operations at major ISPs; an algorithm
  change means every ISP upgrading CMTS software simultaneously with every modem
  being re-provisioned.

## impact

DOCSIS BPI+ is what separates paying subscribers from free-riders and what encrypts
residential broadband traffic on the coax trunk. break the RSA chain and both
properties collapse.

- factor the CableLabs DOCSIS Root CA RSA key. forge a manufacturer sub-CA cert,
  then forge device certificates for modems you control. register on any CMTS
  as any modem MAC. free cable internet, yes, but also:
- impersonation: register as a legitimate subscriber's modem (MAC spoofing + forged
  cert) and intercept their downstream traffic. CMTS ciphers to the forged modem's
  RSA key; attacker decrypts; proxy traffic to real subscriber or record.
- **CableLabs DOCSIS Root key compromise would invalidate authentication for every
  cable broadband connection in North America simultaneously**. there is no
  graceful recovery path — re-rooting requires physically replacing or reflashing
  every modem, which for most consumers means a truck roll or box swap.
- HNDL: ISPs record authentication exchanges for regulatory compliance. years of
  recorded BPKM Auth Requests contain every modem's RSA public key plus the RSA-
  encrypted AK. factoring the modem key lets an attacker derive AKs and decrypt
  historical captured cable-link traffic (back to the year of the AK rotation).
- commercial DOCSIS (enterprise cable-fed circuits, business continuity links for
  small banks and retail chains): same RSA chain. forge certificate, intercept
  commercial link traffic.
- DPoE / cable-over-Ethernet gateways: same CableLabs root.

## Code

`docsis_bpi_auth.c` — `docsis_verify_device_cert()` (cable modem cert verification
against CableLabs root), `docsis_encrypt_ak()` (CMTS side, RSA-PKCS1-v1_5 wrap of AES
Authorization Key to modem's RSA public key), `docsis_decrypt_ak()` (modem side),
`docsis_derive_tek()` (AES-128 Traffic Encryption Key derivation from AK).
CableLabs DOCSIS Root trust anchor and BPI+ protocol context in comments.
