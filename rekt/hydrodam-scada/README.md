# Hydroelectric dam / gate-control SCADA — FERC + NERC CIP +
# signed spillway / turbine command chain

Large hydro dams (FERC Part 12 / USACE / BC Hydro / EDF / Statkraft
/ Itaipu Binacional) are jointly power-generation + flood-control
+ fish-passage infrastructure. SCADA controls **spillway gates,
turbine wicket gates, penstock valves, fish ladders, forebay
sluices**, and tailwater monitoring. Under **NERC CIP-003 through
CIP-013** + **FERC Order 822** any operator-issued command touching
a high-impact BES Cyber System is signed.

## Players

- **Dam operators**: Bureau of Reclamation, USACE, TVA, BPA, NY
  Power Authority, BC Hydro, Hydro-Québec, Statkraft, EDF Hydro,
  Iberdrola, Eletrobras, CEZ, Vattenfall
- **SCADA / DCS**: ABB Symphony Plus + Ability, Emerson Ovation
  Hydro, Siemens SPPA-T3000 / SICAM, GE Mark VIe + Proficy,
  Rockwell, Andritz HIPASE
- **Turbine / governor OEMs**: Voith Hydro, Andritz Hydro, GE
  Renewable Energy (Alstom legacy), Toshiba, Harbin Electric
- **Regulators**: FERC + NERC (US), BC OGC / Canadian Dam
  Association, ENTSO-E + EU Water Framework, ANEEL (Brazil)
- **River-forecasting upstream of gate ops**: NOAA NWS River
  Forecast Centers (RFCs), BC River Forecast Centre

## RSA usage

### 1. Spillway-gate command signing
Spillway-gate setpoint changes (raise / lower / fully open) carry
dual-operator signatures. Every command is logged with signatures
and retained 7+ years under FERC Part 12 dam-safety inspection
regime.

### 2. Turbine / wicket-gate dispatch signing
AGC signals from the ISO/TSO (CAISO, ERCOT, PJM, MISO, ENTSO-E
balancing authority) flow with RSA signatures. Local plant
verifies before actuating wicket gates. Mis-dispatch can over-
speed a unit to runaway RPM.

### 3. Flood-ops coordination signing
Flood-season gate operations follow a signed "Water Control
Manual" + daily signed guidance from the regional USACE district
/ BPA / BC Hydro River Ops. Deviations from the signed guidance
are themselves signed + retained.

### 4. Fish-passage protection
ESA / Endangered Species Act-compliant fish-passage events
(bypass flow releases during salmon runs) are signed by
biologist + operator. NMFS-audited signed record is the legal
compliance basis.

### 5. NERC CIP evidence signing
CIP-007 security-event monitoring, CIP-010 configuration change
management, CIP-013 supply-chain signed artefacts. NERC audit
every 3 years draws evidence from signed logs.

### 6. Dam-safety monitoring telemetry
Inclinometers, piezometers, crack meters, surface-mark survey
targets signed into dam-safety monitoring systems (Campbell
Scientific, GeoSIG, SISGEO). Per FEMA / FERC Part 12, signed
telemetry feeds annual dam-safety inspection.

## Scale + stickiness

- Large dams globally: ~60,000 (ICOLD)
- NERC-registered generating hydro units in US: ~4,000
- FERC-licensed hydro: ~2,500 projects
- SCADA installed-base refresh: 20-30 years
- Dam-safety telemetry: often 40+ year continuous signed record

Why RSA stays: NERC CIP references specific cryptographic
profiles (NIST SP 800-53 revision-locked). FERC-licensed projects
re-qualify after architectural changes. Dam-safety records have
multi-decade retention; retroactive re-verification of signed
records spanning decades is not cost-recoverable in a single
rate-case cycle.

## Breakage

- **Operator-credential root factored**: attacker signs spillway-
  gate open commands during flood season, or close commands
  during maintenance-depleted reservoir — downstream flooding or
  upstream overtop failure. Oroville 2017-class incident, but
  with authenticated-looking command history.
- **AGC dispatch signing root factored**: unauthorised unit
  dispatch causes overspeed runaway; turbine-destroying event
  with valid-looking ISO paper trail.
- **River-forecast signing factored**: mis-forecast stimulates
  wrong flood-prep posture — under-release before peak.
- **Dam-safety telemetry signing factored**: creeping instability
  signatures concealed; maintenance-inspection regime defeated.
- **NERC CIP evidence signing factored**: audit posture
  unverifiable; $1M+/day NERC penalties accumulate until
  remediation + regulatory-imposed operating restrictions.
