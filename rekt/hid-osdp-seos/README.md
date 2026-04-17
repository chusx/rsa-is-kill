# HID Global SEOS + OSDP Secure Channel — physical access control

The HID iCLASS SE / SEOS credential platform is the dominant
enterprise physical access control (PACS) technology. Deployed at:

- US federal campuses (under FIPS 201 / PIV-I)
- Most Fortune-500 headquarters, datacenters (Google, Microsoft,
  Meta campuses), hospital systems (HCA, Kaiser, Ascension),
  universities (University of California system, Ivy League),
  DoD facilities, NATO HQ
- Tens of millions of door readers + access panels worldwide

The credential stack has multiple RSA dependencies:

## 1. SEOS / iCLASS SE credential personalization

HID's **Corporate 1000** and **Seos** card programs personalize
smart cards (13.56 MHz ISO 14443) with a site-specific key set.
Card stock is shipped from HID "key-loaded" under an RSA-wrapped
master key — the KMS (Key Management System) and the personalization
appliance (HID Key Loader) negotiate an RSA-based session to
install customer keys.

**HID Origo / HID Mobile Access** for phone-based credentials uses
device attestation (iOS SecEnclave, Android StrongBox) whose
attestation keys chain to vendor root CAs — all RSA.

## 2. OSDP v2.2 Secure Channel Protocol (SCP)

**OSDP** (Open Supervised Device Protocol) is SIA's standard for
reader-to-controller comms, superseding the 40-year-old Wiegand
wire protocol. OSDP v2.2 Secure Channel does AES-128 message
authentication, but the initial **Install Mode key exchange**
between panel and reader is done under an RSA-wrapped one-time
install key. Controller vendors: **Mercury (now HID)**, **Lenel S2**,
**Gallagher**, **Software House iSTAR**, **Genetec Synergis**,
**AMAG**, **Siemens SiPass**, **Bosch AMC2**.

## 3. FIPS 201 / PIV-I interop

For federal deployments, SEOS readers also accept PIV / PIV-I cards
— so the same physical reader terminates both HID proprietary
authentication and the federal PIV authentication (see `piv-cac-
smartcard/`) which is RSA-rooted at DoD and Federal Common Policy
CAs.

## 4. Access control panel ↔ server comms

Lenel OnGuard, Genetec Synergis, AMAG Symmetry, Honeywell Pro-
Watch all speak to their controllers over TLS. Controller certs
are RSA-2048 chained to the customer's enterprise CA or the
vendor's factory root.

## 5. Firmware for readers + panels

Every HID Signo / iCLASS SE reader firmware, every Mercury panel
firmware, every HID Aero / Lenel NX panel firmware is RSA-2048
signed by the vendor release HSM. Firmware update pushed via the
head-end software verifies the signature before flash.

## Scale

- 100+ million SEOS credentials provisioned worldwide
- ~10 million door readers in production
- Every major datacenter, every TSA-regulated airport, every DoD
  Common Access Card issuance station, most critical-infra (NRC-
  regulated nuclear, FERC-regulated transmission substations,
  CISA-designated chemical facilities)

## Breakage

A factoring attack against:

- **HID Corporate 1000 or SEOS master-key-wrap RSA key**: attacker
  extracts the site-specific key set during personalization
  transit. Clone any SEOS credential for any customer site key-
  loaded under the compromised CA. Physical access to every
  corporate/government site using that key set becomes available
  to the holder of a $50 SDR-based credential-emulator.
- **HID reader / Mercury panel firmware-signing CA**: attacker
  signs malicious firmware that logs every credential presentation
  (and silently accepts an attacker credential) at every reader
  in service. Multi-million-reader attack footprint.
- **PIV Common Policy Root** (covered in `piv-cac-smartcard/`):
  attacker mints a PIV card accepted as valid federal credential
  at every PIV-capable reader.
- **Vendor PACS server TLS CA** (Lenel, Genetec): MITM of
  controller↔head-end traffic; override access decisions, forge
  audit logs, mask breaches from SOC monitoring.

Physical security systems are 10-20 year deployed assets. Reader
fleet replacement is a multi-year capital program per facility. A
factoring break is effectively unremediable in the short term for
existing installations.
