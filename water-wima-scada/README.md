# Water / wastewater SCADA — WIMA + AWWA G430 + EPA signed
# telemetry and treatment-chemistry logs

US public-water utilities (EPA-regulated under SDWA + CCR) and
European utilities (under the EU Drinking Water Directive
2020/2184) operate SCADA networks binding **pump stations,
treatment plants, reservoirs, and distribution zones** via signed
telemetry. **AWWA G430 (Security Practices)** + **WaterISAC** +
**CISA cross-sector goals** baseline the security posture. Chlorine
residual, fluoride dosing, turbidity, and pressure records are
regulator-auditable signed artefacts.

## Players

- **SCADA / ICS vendors**: Rockwell FactoryTalk / ControlLogix,
  Siemens SIMATIC WinCC / PCS 7, GE Proficy iFIX / CIMPLICITY,
  Schneider Wonderware / ClearSCADA, Emerson Ovation Water, ABB
  Symphony Plus, Survalent ADMS/SCADA, Trihedral VTScada, INDUSOFT
- **RTU / PLC**: Rockwell MicroLogix / CompactLogix, Schneider
  SCADAPack, GE RX3i, Mitsubishi MELSEC, Siemens S7-1500
- **Telemetry radio / cell**: FreeWave HTplus, MDS SD-series,
  Sierra Wireless / Digi cellular gateways
- **Utilities (examples)**: DC Water, LADWP, NYCDEP, SFPUC, Thames
  Water, Scottish Water, VCS (Copenhagen)
- **Regulators**: US EPA (SDWA + America's Water Infrastructure
  Act), NSF/ANSI 61 for materials, state public-utility commissions

## RSA usage

### 1. Plant-to-utility-HQ signed telemetry
Treatment-plant SCADA historian (OSIsoft PI, GE Proficy Historian,
Aveva Historian) signs telemetry summaries before cross-firewall
export to corporate/BI systems. EPA MRL (monthly reporting) draws
from signed historian exports.

### 2. Operator-initiated command signing
Dose-rate changes (chlorine, fluoride, polymer), valve setpoints,
pump start/stop — operator console signs with the operator's
credential. Signed command record retained per AWIA + state PSC.

### 3. Regulatory report signing (EPA CCR, LT2ESWTR, CWS)
Consumer Confidence Reports, compliance monitoring, and
laboratory results submitted to state primacy agencies + EPA
SDWIS are signed. CWS (lead + copper rule revisions) ELD
compliance depends on signed lab chain.

### 4. Inter-utility mutual-aid signing
Under WARN (Water/Wastewater Agency Response Network), mutual-
aid requests during emergencies (ice storms, cyberattacks,
wildfires) carry signed resource manifests — equipment, operators,
chemicals loaned.

### 5. Chemical-delivery manifest signing
Tanker deliveries of bulk chlorine, sodium hypochlorite,
fluoride, alum, lime: dispatch manifests from supplier (Brenntag,
Univar Solutions, Olin, Occidental) are signed; utility receiving
clerk counter-signs, binding lot numbers to treatment-event logs.

### 6. Cyber-incident forensics anchoring
Following Oldsmar (FL, 2021) + Aliquippa (PA, 2023) + Muleshoe
(TX, 2024) incidents, signed SCADA event logs are the forensic
substrate for CISA + FBI attribution.

## Scale + stickiness

- US community water systems: ~50,000 (SDWA)
- US wastewater utilities: ~16,000
- EU utilities under DWD 2020/2184: ~80,000
- Typical utility SCADA refresh: 15-25 years
- Regulatory reporting cadence: daily → monthly → annual CCR

Why RSA stays: AWWA + AWIA + EU DWD do not mandate crypto
modernisation. Utility capex is rate-payer-funded — replacement
cycles are decades. OT network segmentation + signed commands
are the primary integrity controls; any crypto migration requires
coordination across vendor + integrator + regulator in each of
50+ US states.

## Breakage

- **Utility operator-credential root factored**: attacker signs
  dose-rate changes — overdose chlorine / underdose disinfection
  at scale. Oldsmar/Aliquippa-class attack with valid-looking
  audit trail.
- **Historian / regulatory-export signing key factored**:
  fabricated compliance reports hide MCL exceedances; or genuine
  compliance reports are denied after mass CCR forgeries
  destroy EPA data integrity.
- **Chemical-supplier manifest root factored**: deliberate
  misrepresentation of chemical lot concentrations (diluted
  chlorine) — silent treatment failure traceable only after a
  boil-water incident.
- **Inter-utility mutual-aid signing root factored**: false
  emergency-aid requests divert resources; real emergencies
  trigger slower response due to verification burden.
