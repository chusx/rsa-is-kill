# Forensic evidentiary breathalyzers — signed BAC measurements
# and chain-of-custody

DUI / DWI prosecutions in the US, UK, Germany, Australia, and
elsewhere depend on **evidentiary-grade breath-alcohol
instruments** whose measurements are signed into a chain of
custody. An instrument whose signature fabric is compromised
invalidates every DUI conviction that depended on its output —
retrospectively, across years of casework.

## Players

- **Instrument makers**: Intoximeters (Intox EC/IR II, Alco-
  Sensor V / VXL), Dräger (Alcotest 9510 / 7510 / 6820), CMI
  (Intoxilyzer 8000 / 9000), Lion Laboratories (Lion Intoxilyzer
  800), Envitec AlcoQuant
- **Regulators / calibration**: NHTSA (US Conforming Products
  List for evidential breath testers), Forensic Science
  Regulator (UK), BPhA / PTB (Germany), NATA (Australia)
- **Agencies**: state/county DUI enforcement, Bundespolizei,
  UK police forces, state toxicology labs, military MPs

## RSA usage

### 1. Per-subject breath-test record signing
Each subject test produces a signed record: timestamp, subject
ID, officer ID, the two duplicate BAC readings (most jurisdictions
require two separated by several minutes), ambient conditions.
The signed PDF or XML artefact is the evidentiary exhibit.

### 2. Calibration-check + simulator-solution signing
Calibration checks (wet-bath or dry-gas simulator) run daily or
per-shift. The calibration record — including simulator
solution lot number + expected value + observed value — is
signed. Defence counsel routinely subpoenas these records.

### 3. Firmware + algorithm signing
Core breath-measurement algorithm (IR + fuel-cell dual-sensor
correlation) is under **Frye/Daubert** admissibility scrutiny.
Any change to firmware triggers admissibility challenge in
every active case. Vendor signs firmware; courts have in some
jurisdictions (Wisconsin, New Jersey) demanded signature
provenance evidence during discovery.

### 4. Officer-authentication chain
The officer operating the instrument authenticates with a
credential that chains to the agency's signing root. Some
jurisdictions (Germany, Australia) require two-witness signed
attestation on the breath record.

### 5. State-lab dispatch + archival signing
Signed records flow to the state toxicology lab or forensic
services, whose archival signing protects the chain of custody
until statute of limitations (often 5-10 years + appeals).

## Scale + stickiness

- US DUI arrests/year: ~1M
- Evidential breathalyzers in US: ~20,000 instruments
- Vendor firmware cycles: 5-10 year major versions; minor
  updates trigger courtroom admissibility reviews
- Once an instrument-make ships an "approved" firmware, swapping
  the crypto requires re-approval on **every state's** CPL

Why RSA stays: Frye/Daubert admissibility tests freeze the
cryptographic architecture that was accepted. NHTSA's CPL and
state conforming-products lists reference specific firmware
builds. Replacing RSA means revisiting admissibility in every
state supreme court.

## Breakage

- **Vendor firmware signing root factored** (Dräger / Intox /
  CMI): defence argues all signed records from that vendor are
  no longer authenticatable. Mass vacatur of DUI convictions
  where signature provenance was probative. Massachusetts
  Annie Dookhan-scale disruption, but at crypto layer rather
  than procedural.
- **Agency officer-credential root factored**: forged-officer
  breath records injected into case files; genuine records
  become indistinguishable from fakes. Prosecution discovery
  obligations explode.
- **Calibration signing root factored**: defence argues
  instrument's calibration history unverifiable — triggers
  individual-case challenge in every active DUI prosecution
  that cited that instrument.
- **State-lab archival root factored**: decade-deep evidence
  chains unverifiable; appeals on closed convictions reopen.
