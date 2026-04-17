# USPS IMI / Royal Mail / Deutsche Post / La Poste — digital
# postage-indicium signing, franking-machine PKI

Every piece of mail carrying a "pay at home / pay at office" postage
indicium in the US, UK, Germany, France, Canada, Australia, Japan
is stamped under a **digital indicium** scheme where the machine-
readable 2D barcode includes a **cryptographic signature** over the
postage amount, serial number, destination ZIP, and sequence. The
postal operator verifies at the induction mail-processing facility.

In the US this is **USPS Information-Based Indicia (IBI)**, upgraded
2020–2024 to **IMI (Intelligent Mail Indicia)**. Globally
equivalents: UK Royal Mail **Smart Stamp**, Deutsche Post **Frankit
/ Briefe+ online**, La Poste **MaqueStamp**, Canada Post **e-stamp**,
Australia Post **Digital Stamp**.

## Core players

- **Pitney Bowes** (~60% global franking market) — SendPro, DM
  series, IntelliLink Control Center
- **Neopost / Quadient** (~25%)
- **FP Mailing Solutions, Francotyp-Postalia, Hasler** (~10%)
- **Stamps.com / Auctane / Endicia** (US PC-postage)
- **ShipStation, ShippingEasy, EasyPost** (e-commerce rate
  shopping; PC-postage indicium issuers)

## RSA usage

### 1. Indicium-signing keys per-meter
Every physical franking meter (office postage-meter) and every PC-
postage user account holds an RSA key pair bound by the USPS
Postal Security Device (PSD) provisioning CA. The meter signs each
indicium (piece of mail's 2D barcode) with its private key over
the postage data + a monotonic ascending register.

### 2. USPS / Royal Mail verification CA
At the processing facility, MLOCR (Multi-Line OCR) + barcode readers
decode the indicium and verify the signature against the operator-
wide PSD trust store. Descending / ascending-register mismatches,
bad signatures, and duplicates are tagged for postal-inspection
service referral (this is a federal felony under 18 USC §1001/1341
for fraudulent use).

### 3. PSD firmware signing
PSDs (the secure module inside the franking meter) ship firmware
signed by the vendor (Pitney Bowes, Quadient, FP) and validated
by the USPS Engineering Acceptance Lab. USPS regulations require
a USPS-counter-signature for production releases of PSD firmware.

### 4. Postal inspector track-and-trace integrity
IMb (Intelligent Mail barcode) scans at every processing centre
feed the IV-MTR (Informed Visibility Mail Tracking & Reporting)
system. Business-mail-entry-unit (BMEU) scanning authenticated by
business-partner RSA certs.

### 5. International postal exchange (UPU S-series)
Universal Postal Union's S43, S58, S60 messaging standards between
designated postal operators use mutually-authenticated TLS and
signed electronic advice-of-shipment. Cross-border parcel
manifests (CN 23 customs declarations, ITMATT / CUSITM / CUSRSP
EDI) carry signatures.

### 6. Drone / autonomous-delivery pilots
USPS, Royal Mail, Swiss Post pilots of drone delivery carry signed
package manifests tied to the address and recipient. Every
package-to-drone bind event is cryptographically logged.

## Scale

- US mail volume: ~115 billion pieces/year
- Of those, ~60 B pieces carry metered / PC-postage indicium
- ~2 million active franking meters in the US
- Pitney Bowes alone maintains ~1.2M active machines globally
- Parcel volume (Amazon, UPS, FedEx, USPS): ~200B pieces/year
  globally — digital-shipping-label authentication relies on
  carrier CA trust chains

## Breakage

A factoring attack against:

- **A USPS PSD provisioning CA (or equivalent in RM / DPAG / LP)**:
  attacker mints unlimited "legitimate" indicium signatures.
  Postage fraud at federal-felony scale. USPS estimates several
  $100M/year in attempted indicium fraud today; a factoring
  break removes the verification barrier entirely.
- **A vendor PSD firmware root (Pitney Bowes etc)**: fleet-wide
  meter compromise → mass postage-theft, or silent overcharging
  of customer accounts (revenue-manipulation attack).
- **A UPU international-exchange CA**: cross-border customs-
  declaration forgeries enable smuggling cover (drug/weapons
  interdiction relies on these manifests).
- **A PC-postage account issuer (Stamps.com/Auctane) CA**: any
  attacker can print valid indicium in any customer's name;
  e-commerce fulfilment integrity collapses.

Franking-meter fleet lifecycle: 7–12 years. A PSD-CA compromise
needs a USPS-coordinated roll of ~2M US meters plus every PC-
postage account — a multi-year programme for a product whose
operational purpose is that it exists as trusted substitute for
paper stamps.
