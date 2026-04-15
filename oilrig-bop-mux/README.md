# Offshore oil-rig blowout preventer (BOP) + subsea MUX —
# signed well-control commands under BSEE 250.734

Post-**Macondo / Deepwater Horizon (2010)**, US offshore drilling
on the OCS is subject to **30 CFR 250 subpart G (well control
equipment)** + **BSEE real-time monitoring rules** + **API Spec
16D** + **API RP 53/64/96**. The BOP stack — the 400-ton valve
assembly on the sea-floor — is the last-line well-control
barrier. Subsea Multiplex (MUX) control systems and surface
driller's console commands that actuate BOP rams (pipe, blind-
shear, casing-shear) are increasingly cryptographically signed
under operator + BSEE RTM programmes.

## Players

- **BOP OEMs**: Cameron (Schlumberger / SLB post-2023), NOV
  (National Oilwell Varco), GE / Baker Hughes, Aker Solutions
- **MUX control-system vendors**: TechnipFMC, Baker Hughes
  Subsea Controls, Aker Solutions, Siemens Subsea, Proserv
- **Drilling contractors**: Transocean, Valaris, Noble, Seadrill,
  Stena Drilling, Maersk Drilling (now Noble), COSL, Odfjell
- **Operators (leaseholders)**: ExxonMobil, Shell, BP, Chevron,
  TotalEnergies, Equinor, Petrobras, Aramco, CNOOC, ONGC
- **Regulators**: BSEE (US Gulf of Mexico + Alaska OCS), PSA
  Norway, UK HSE OSD + NSTA, ANP Brazil, NOPSEMA Australia

## RSA usage

### 1. BOP-stack firmware + MUX control-pod signing
BOP stack control pods (Yellow + Blue redundant pods) run signed
firmware. The MUX encoding of driller's-console commands over
the umbilical is authenticated; pod rejects commands failing
verification to minimise spurious actuation.

### 2. Shear-ram / casing-shear command signing
Blind-shear ram and casing-shear ram are the last-resort barriers.
Actuation is a two-person signed authorisation (OIM + toolpusher,
or operator company-man + driller) at the surface, with the
signed command transported down the umbilical to the subsea pod.

### 3. Pressure-test + function-test result signing
BOP pressure tests (every 14 days, API RP 53), function tests
(weekly), and ram-operation signatures are signed. Post-Macondo
BSEE reviews depend on signed evidentiary chain for witness-
tested BOP components.

### 4. Real-time monitoring (RTM) to onshore center
Mud-logging, kick-detection, pit-volume, SPP/HSP telemetry is
signed and streamed to the operator's onshore real-time
operations center (RTOC) — ExxonMobil ROC, Shell RTOC, Chevron
iCBMT. Signed RTM is evidentiary in incident investigation.

### 5. Well-control emergency bridging (EDS)
Emergency Disconnect Sequence (EDS) initiation from the rig
floor in a dynamic-positioning-loss scenario — signed commands
with envelope-bound timings.

### 6. Operator → contractor well-plan signing
The drilling-programme + well-construction-plan + mud-weight
window are signed artefacts handed from operator's drilling
engineer to rig. Hand-off is signed + counter-signed (operator
company-man + drilling contractor rig-manager).

## Scale + stickiness

- Active offshore rigs globally: ~600-700 (after ~40% reduction
  from 2014 peak)
- US OCS active drilling-unit registrations: ~100
- BOP stack useful life: 20-25 years with refurb cycles
- Firmware upgrade cycles: infrequent; each requires BSEE
  pre-approval under 30 CFR 250.734

Why RSA stays: BSEE + PSA + NSTA regulatory approval locks
specific cryptographic profiles into the well-control equipment
certification. Post-Macondo scrutiny made BSEE + API hesitant
on any architectural change. Offshore BOP costs $20-50M per
stack + $150k-$1M/day rig dayrate — any re-cert involves years
of well downtime.

## Breakage

- **BOP OEM / MUX vendor firmware signing root factored**:
  attacker installs malicious subsea-pod firmware. Last-line
  well-control barrier silently inoperative — Macondo-class
  blowout without the malicious-insider attribution pathway.
- **Rig OIM / operator company-man signing root factored**:
  forged ram-actuation + EDS commands — spurious shear-ram
  activation destroys drill-pipe + wellbore integrity
  (~$100M+ well-loss event).
- **Operator onshore RTOC signing root factored**: RTM streams
  from rig floor unverifiable, incident investigation chain
  broken. BSEE forced to impose operating restrictions.
- **Pressure-test result signing factored**: API RP 53 test
  compliance unprovable; regulator forces fleet-wide manual
  witness re-tests.
