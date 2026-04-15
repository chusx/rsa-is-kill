# Wind turbines — SCADA / IEC 61400-25, signed turbine-controller
# firmware, grid-services auth

The global wind-power fleet has a **cumulative installed capacity
of ~1,000 GW across ~400,000 individual wind turbines** as of
2024 (onshore + offshore). Major OEMs:

- **Vestas** (Denmark) — ~20% global share
- **Goldwind** (China) — ~15%
- **Siemens Gamesa Renewable Energy** (Germany/Spain) — ~14%
- **GE Vernova** (USA) — ~10%
- **Envision, Mingyang, Nordex, Enercon, Suzlon** — rest

Each turbine is a 3–15 MW electromechanical machine with a
controller (Vestas VestasOnline, Siemens Gamesa WebWPS, GE
MarkVIe, Goldwind Fortune). Above the turbine is a park SCADA
(site supervisory) and above that a fleet operations centre.

## Relevant standards

- **IEC 61400-25** — communications for wind-power plant monitoring
- **IEC 62443** — industrial automation cybersecurity
- **IEEE 1547 / 1547.1** — DER interconnection requirements
- **NERC CIP** (North American bulk-power) — applies to wind
  plants over 75 MVA
- **EU NIS2** — extended OT cybersecurity reach to operators of
  essential services including wind

## RSA usage

### 1. Turbine-controller firmware signing
Every modern turbine controller accepts OTA firmware updates over
the park LAN. Vestas, Siemens Gamesa, GE, Goldwind all sign
firmware. Safety-critical pitch / yaw / brake logic is signed by
a distinct safety-controller key subject to TÜV certification
(IEC 61508 SIL 2).

### 2. IEC 61400-25 MMS + TLS mutual auth
MMS-over-TCP (IEC 61850 family) between turbine and park SCADA
uses certificate-based mutual auth in modern deployments. Per-
turbine RSA certs issued by the OEM factory or by the operator's
plant PKI.

### 3. Grid-services / ISO/RTO interaction
In ERCOT, CAISO, PJM, MISO, National Grid ESO, European TSOs,
wind plants bid Ancillary Services (frequency response, reserves)
through signed telemetry + dispatch messages. The same RSA trust
chain supports IEEE 2030.5 CSIP-inspired utility-to-DER messages
and IEEE 1547 inverter-based-resource controls.

### 4. Blade / gearbox condition-monitoring to OEM cloud
Vestas CMS / OnePM, Siemens Gamesa Diagnostic Service Center,
GE Predix (now Meridium APM), Goldwind GOPS — TLS mutual auth
with per-turbine client certs. Vibration, temperature, oil-debris,
strain-gauge streams.

### 5. Inverter/converter firmware (wind + solar + storage shared)
Power-electronics inverters come from ABB, Siemens, Ingeteam,
SMA, Huawei, Sungrow. Firmware signing is RSA-based today;
standards push (UL 1741 SB / SA, IEC 62443-4-1) aligning
requirements across wind + solar + battery storage.

### 6. Offshore-wind SCADA
Offshore parks (Ørsted, Ørsted-EQT, Equinor, Iberdrola, Vattenfall)
have an additional subsea-cable-mux / HVDC converter SCADA layer.
Siemens, Hitachi-ABB, GE Vernova HVDC converter stations use RSA-
backed PKI for control-and-protection messages.

## Scale

- ~400,000 wind turbines globally (~3,000 GW deployment target 2030)
- Annual new installations: ~100 GW/year (~8,000 turbines)
- Wind generates ~10% of global electricity and rising
- ERCOT (Texas) alone: ~40 GW installed wind + solar, grid-
  stability dependent on IBR (Inverter-Based Resources) staying
  connected during events (e.g. Feb 2021 grid crisis)

## Breakage

A factoring attack against:

- **Vestas / Siemens Gamesa / GE / Goldwind firmware-signing root**:
  signed firmware deployed fleet-wide that either (a) trips every
  turbine offline simultaneously — sudden loss of 100s of GW causes
  cascading grid instability; or (b) disables pitch-control safety,
  letting rotors overspeed to structural failure, ejecting tens-of-
  tonnes blades at 80 m/s tip velocity across populated terrain.
- **Grid-services signing root**: forged telemetry / dispatch
  during frequency events; inverters refuse legitimate grid-
  support commands, or execute malicious ones (e.g. simultaneous
  disconnection during a low-frequency event, accelerating
  cascading blackout à la 2003 Northeast, 2006 UCTE Europe).
- **HVDC / offshore-converter PKI**: bilateral HVDC links (NordLink,
  Viking Link, NeuConnect) disruption — multi-GW cross-border
  power interruption.
- **OEM cloud CA**: fabricated predictive-maintenance alarms
  forcing plant-wide service outages; or the opposite — silent
  suppression of bearing-failure warnings leading to multi-$M
  gearbox replacements or catastrophic nacelle fires.

Wind-turbine lifecycle: 20–25 years. A vendor firmware-root
compromise affects every unit in service; replacement of pitch/
yaw/brake safety controllers requires tower + nacelle + hub
access — scaffolding, rope-access, or offshore jack-up vessels.
Scheduling is weather-constrained and expensive (offshore repair
visits run ~€100k/day all-in).
