# Nuclear power plant I&C — IEC 61513 / IEEE 7-4.3.2 / NRC RG 1.152
# signed safety + control-system artefacts

Light-water reactors (PWR + BWR + VVER + CANDU), advanced reactors
(EPR, AP1000, APR1400, ABWR, HPR-1000 "Hualong One", VVER-1200),
SMRs (NuScale VOYGR, BWRX-300, Rolls-Royce SMR), and research
reactors (TRIGA, OPAL) run **safety-classified instrumentation &
control (I&C)**: **Class 1E** (safety-critical) separated from
non-safety. Under **IEC 61513 + IEC 62645 (cybersecurity) + IEEE
7-4.3.2 + US NRC RG 1.152 Rev 3 + 10 CFR 50.55a(h)**, safety-I&C
software + parameter changes + qualification records are signed.

## Players

- **Safety-I&C platforms**: Framatome TELEPERM XS / TXS (EPR +
  many VVERs), Westinghouse Common Q / Ovation, Rolls-Royce Spinline
  (Chinese EPR + Korean APR1400), Mitsubishi MELTAC-N+, Hitachi
  HIACS-7000, Doosan POSAFE-Q, Rosatom (TPTS)
- **Non-safety control**: Emerson Ovation, Siemens TELEPERM ME /
  SPPA-T2000, Westinghouse Ovation, ABB Procontrol P14 / Symphony
  Plus, Yokogawa CENTUM VP
- **Utilities**: EDF, Exelon/Constellation, Dominion, Duke, TVA,
  Ontario Power Gen, Bruce Power, KEPCO/KHNP, TEPCO, Kansai EPCO,
  EDF Energy UK, CEZ, Vattenfall, Rosatom AtomStroyExport
- **Regulators**: NRC (US), ASN/IRSN (France), ONR (UK), STUK
  (Finland), CNSC (Canada), NRA (Japan), NNSA (China)

## RSA usage

### 1. Safety I&C application software signing
Reactor Protection System / Engineered Safety Features Actuation
System / Reactor Trip System software loads are signed by the
I&C platform vendor under a safety-classified PKI. Equipment
refuses any unsigned load.

### 2. NRC / ASN / ONR qualification-record signing
Pre-operation qualification reports (Commercial Dedication,
Equipment Qualification under 10 CFR 50.49, EMC / seismic)
are signed. Regulator audit draws on signed retention.

### 3. Surveillance-test + technical-specification-required-action signing
Periodic surveillance tests of safety components (battery-
capacity, diesel-gen start, valve stroke times, SDM calc) are
signed by the technician + STA. Signed completion is the tech-
spec LCO compliance evidence.

### 4. Fuel-handling + refueling signing
Refueling outage core-loading sequences, fuel-assembly
identifications, and boron-dilution signatures are signed.
Criticality-safety depends on signed core-map adherence.

### 5. Cyber-security program signed artefacts (NRC 10 CFR 73.54)
Cyber program baseline configurations, quarterly assessments,
response-plan artefacts — all signed under 10 CFR 73.54.
Inspector-general audit verifies signed chain.

### 6. Fleet-common signed parameter distribution
For multi-unit utilities (EDF 56-unit fleet, KHNP 25-unit fleet),
fleet-common parameter changes (e.g. ageing-management setpoint
updates) are signed at the utility's engineering authority and
distributed to each unit's I&C.

## Scale + stickiness

- Operating commercial reactors worldwide: ~440
- Under construction: ~60
- Typical licensed life: 40 years initial + 20-year renewal ×2
  (up to 80 total under NRC subsequent license renewal)
- Digital I&C upgrade programmes: ~$500M-$1B per plant,
  20-year cycles
- NRC 10 CFR 50.59 + regulatory-review overhead on any
  safety-I&C change: measured in years per plant

Why RSA stays: IEC 61513 / IEEE 7-4.3.2 clauses reference
specific cryptographic assurance. Licence-basis changes require
regulator pre-approval. Post-Fukushima regulator scrutiny on
safety-I&C is at maximum — no utility wants to be the pilot
plant for a post-quantum migration.

## Breakage

- **Safety-I&C vendor signing root factored** (TXS / Common Q /
  Spinline / MELTAC): attacker-loaded RPS software in vulnerable
  units. The most severe single identifiable crypto-failure
  scenario in this catalog. Multi-country nuclear-safety
  regulatory crisis.
- **Utility engineering-authority root factored**: forged
  fleet-common parameter changes — coordinated degradation
  across multi-unit fleet.
- **Regulator qualification root (NRC / ASN) factored**:
  qualification-records authenticity destroyed; regulator
  forced to impose operating restrictions pending manual
  reverification of every plant's Q-file.
- **Cyber-program signing factored**: 10 CFR 73.54 compliance
  posture uncheckable; $250k/day + NRC CALs accumulate.
- **Fuel-handling signing factored**: mis-loaded core map with
  forged compliance — criticality-safety assumptions violated.
