# Refinery / petrochemical Safety Instrumented Systems —
# IEC 61511 SIL-rated trip logic + signed parameter changes

Refineries, ethylene crackers, LNG liquefaction, fertiliser plants,
and offshore platforms run **Safety Instrumented Systems (SIS)**
independent of the BPCS (Basic Process Control System). Under
**IEC 61511 / IEC 61508** the SIS implements **SIF**s (Safety
Instrumented Functions) at **SIL 1-3** (occasionally SIL-4).
Parameter changes, logic-solver recipe updates, and proof-test
records are cryptographically bound — MoC (Management of Change)
is a regulator-audited workflow anchored in signed artefacts.

## Players

- **Safety-PLC vendors**: Siemens Simatic S7-1500F / S7-400FH,
  HIMA HIMax / HIMatrix, Rockwell ControlLogix GuardLogix + AADvance,
  Schneider Tricon (Triconex) / TriStation, ABB AC 800M HI, Yokogawa
  ProSafe-RS, Emerson DeltaV SIS (CHARMS)
- **End users**: ExxonMobil, Shell, Chevron, TotalEnergies, BP,
  Aramco, Sinopec, SABIC, Dow, BASF, LyondellBasell
- **EPC / SI**: Bechtel, Fluor, Jacobs, Wood plc, KBR, Yokogawa
  Solutions Service
- **Assessors (FSA)**: TÜV Rheinland / TÜV SÜD / exida — SIL
  certificates on both vendor equipment AND application logic
- **Historic incident context**: Triton/Trisis (2017, Saudi Arabia
  petrochem plant) specifically targeted Triconex — signed-
  firmware integrity is the control of last resort

## RSA usage

### 1. Logic-solver firmware + application-program signing
Vendor signs SIS firmware under a SIL-certified PKI. Application
logic (the end-user's SIF implementations — e.g. high-pressure
trip on reactor R-101) is signed after FSA (Functional Safety
Assessment). Logic solver refuses to boot mismatched firmware or
load unsigned app programs.

### 2. MoC (Management of Change) parameter-change signing
Setpoint changes (trip thresholds, bypass timers) are signed in
the MoC workflow by the Process Safety Engineer + independent
reviewer. SIS records the signed change in its engineering-
history record for regulator audit (OSHA PSM, EU Seveso III).

### 3. Proof-test result signing
Periodic proof tests (SIL-2: typically every 1-3 years; SIL-3:
every 6-12 months) generate signed records that feed back into
SIL verification calcs. The signed record is the durable
evidence that PFDavg remains within target.

### 4. Bypass / inhibit authorisation
Temporary bypass of a trip (for maintenance) requires signed
authorisation with time-limit. SIS enforces automatic un-bypass
at expiry; signed event log feeds into the operations-risk
review.

### 5. Historian / CMMS integration
Maintenance tickets (SAP PM, IBM Maximo, GE APM) corresponding to
safety-device work orders close out against signed SIS telemetry.
Regulator-admissible maintenance history depends on signed chain.

## Scale + stickiness

- Global installed safety-PLC base: ~250,000 systems
- Average lifetime: 20-25 years
- Typical refinery: 100-300 SIFs across ~20 logic-solver chassis
- SIL recertification after any crypto architectural change is
  per-end-user-site + per-EPC-contractor — uneconomic for vendors
  to push proactively

Why RSA stays: functional-safety certification is specific to
cryptographic implementations. IEC 61508 Annex F / IEC 61511 clause
11 freeze the "proven-in-use" crypto. Stuxnet + Triton demonstrated
the severity of any integrity loss — but the response was harder
code-signing, not algorithm change.

## Breakage

- **Vendor SIS firmware root factored** (Triconex / Simatic F /
  HIMA HIMax): attacker installs malicious safety-logic solver
  firmware across vendor installed-base — Triton-class attack
  without the implementation fragility of the 2017 original.
  Trip functions disabled while appearing healthy.
- **End-user MoC signing key factored**: attacker forges setpoint
  changes that slide trip thresholds outside safe envelope
  (e.g. raise high-pressure trip 5% above mechanical design
  pressure) — eventual process-safety incident with forged-legit
  MoC paper trail.
- **FSA signing authority (TÜV / exida) factored**: SIL certs
  on application logic untrustworthy — regulators force plant
  shutdown pending independent reverification.
- **Bypass authorisation root factored**: attacker extends
  bypass windows indefinitely — silent erosion of protective
  envelope.
