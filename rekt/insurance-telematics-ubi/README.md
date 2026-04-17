# Usage-based insurance (UBI) telematics — signed trip records,
# OBD-II dongle firmware, driving-score integrity

**Usage-based insurance** (UBI / pay-per-mile / pay-how-you-drive)
rates auto policies from **telematics data** collected from the
driver's vehicle. Premium-adjusted policies depend on the
cryptographic integrity of that data; if drivers could forge trip
records, the premium model collapses.

## Main platforms

- **Progressive Snapshot** (USA, ~5M active)
- **State Farm Drive Safe & Save** (~2M)
- **Allstate Drivewise / Milewise** (~2M)
- **GEICO DriveEasy, Nationwide SmartRide, Farmers Signal,
  Liberty Mutual RightTrack, Travelers IntelliDrive**
- **Root Insurance** — telematics-first carrier, pure-app model
- **Metromile** (acquired by Lemonade) — pay-per-mile
- **Admiral LittleBox** (UK young-driver TBB market)
- **UnipolSai UnipolMove** (Italy, large market)
- **Zubie / CalAmp / Geotab** — OEM-agnostic OBD-II dongle platforms

Vehicle OEMs operate adjacent programmes where the OEM sells
telematics data to insurers directly: **GM OnStar Smart Driver,
Ford Data Services, Toyota Insure Connect, Honda HondaLink** — all
flowed into LexisNexis Risk Solutions for consolidated driving-
behaviour scoring.

## RSA usage

### 1. OBD-II / in-vehicle dongle firmware signing
Dongles (Progressive Snapshot, CalAmp LMU, Geotab GO, Zubie) ship
signed firmware. Rogue firmware that silently discards hard-braking
events would let a driver score perfectly regardless of behaviour —
so OEMs sign + devices boot-verify.

### 2. Trip-record signing
Every trip record (GPS polyline, accel/decel events, phone-use
events, time-of-day, speeding-over-limit samples) is signed by the
dongle or the mobile SDK before upload. Insurers' backends verify
the signature and chain-of-custody metadata before rating.

### 3. Insurer backend ingest TLS
Mutual TLS between the dongle/app and the insurer cloud. Per-
device RSA certs (TPM-backed on dongles that have one) or per-
account mobile attestation (App Attest, Play Integrity) wrapping
an RSA-authenticated session.

### 4. OEM direct feeds
When OEM supplies the telemetry (OnStar → LexisNexis), the OEM-to-
data-broker link uses signed record envelopes. A flow like:
GM → LexisNexis Drive Score → insurer quote engine. Each hop
signs.

### 5. Usage-based commercial telematics
Fleet insurance uses Samsara, Motive (KeepTruckin), Geotab, Lytx,
Nauto — each signs driver-facing risk events (fatigue detection,
distraction, near-miss) with an RSA chain tied to the vehicle VIN
for insurance + FMCSA HOS compliance.

### 6. LexisNexis / Verisk data-broker attestation
The consolidated driving-behaviour database is itself sold to
insurers with signed extracts; consumers in CA / VA / CO (CCPA
equivalents) can dispute, and the signature chain is the provenance
record.

## Scale

- ~20M active UBI policies in the US
- ~40M globally
- OEM-native telematics footprint: ~150M connected vehicles in
  North America alone; every 2020+ vehicle is a potential telematics
  source
- Insurance industry premium base touched: >$300B annually

## Breakage

A factoring attack against:

- **A dongle-vendor firmware root** (CalAmp, Geotab, Zubie, AutoPi):
  signed firmware that filters out bad-driving events on every
  device fleet-wide. Insurers over-discount ~$10B in annual
  premium if the manipulation is applied invisibly.
- **A trip-record signing root**: any actor can fabricate or
  swap trip telemetry — forge a perfect driving history to earn
  a discount, or forge reckless driving on a third party as
  harassment. LexisNexis Drive Score gets poisoned into
  uselessness.
- **An OEM telematics CA** (GM OnStar etc): forged vehicle-
  generated records flow straight into insurance pricing and
  — via the same ingestion path — into **subpoena-delivered
  evidence** used in civil-injury and criminal-homicide cases
  ("the OnStar log shows the defendant was going 90 mph").
  Evidence-integrity implications are profound.
- **A commercial-telematics root** (Samsara, Motive, Geotab):
  FMCSA HOS compliance records forged. A trucking firm could
  cover for over-hours driving that precedes a fatal crash;
  CSA scores forged; insurance fraud at fleet scale.

Dongle / in-vehicle telematics hardware lifecycle: 3–7 years.
Mobile SDK attestation rotates faster. OEM embedded modem
(TCU / BCM) lifecycle matches vehicle life (10–20 years) — an
OEM-root compromise affects every model year still in service.
