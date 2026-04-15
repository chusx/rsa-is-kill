# Implantable cardiac devices / CIEDs — signed pacemaker and ICD
# firmware, programmer authentication, remote-monitoring upload

**Cardiac Implantable Electronic Devices (CIEDs)** — pacemakers,
implantable cardioverter-defibrillators (ICDs), cardiac
resynchronisation therapy devices (CRT-P / CRT-D), implantable
loop recorders (ILRs) — are present in **~3 million patients
worldwide** with ~1M+ new implantations per year.

Major manufacturers:

- **Medtronic** (USA) — Azure, Percepta, Cobalt, Claria, LINQ II
- **Abbott / St. Jude Medical** (USA) — Assurity, Gallant, Neutrino,
  Ellipse, Confirm Rx
- **Boston Scientific** (USA) — Accolade, Visionist, Resonate, LUX-Dx
- **Biotronik** (Germany) — Rivacor, Edora, Amvia
- **MicroPort CRM** (Sorin legacy) — Kora, Alizea

Adjacent: Neuromodulation (deep-brain stimulators, vagal nerve
stimulators, spinal-cord stimulators) — same vendors + NeuroPace,
Nevro, Axonics.

## RSA usage

### 1. Device firmware signing
Every implant has firmware that receives over-the-wire updates
during clinic visits or remotely (via bedside monitor). Post-
FDA 2017 St Jude / Abbott recall (pacemaker firmware updated
for cybersecurity), every vendor ships RSA-signed firmware
images; the implant's bootloader refuses unsigned updates.

### 2. Programmer / clinician-device pairing
The in-clinic programmer (Medtronic CareLink, Abbott Merlin
Patient Care System, Boston Scientific LATITUDE Programmer,
Biotronik Renamic) pairs with the implant via NFC + short-range
telemetry (MICS-band ~402-405 MHz, Bluetooth LE on newer
devices). Pairing session authenticates via RSA chain; programmer
holds a per-unit leaf cert issued by OEM.

### 3. Bedside-monitor remote-follow-up upload
Patients take a bedside monitor home — Medtronic MyCareLink,
Abbott merlin.net Patient Care Network, Boston Sci LATITUDE NXT,
Biotronik Home Monitoring. It reads the implant's diagnostics
nightly and uploads over cellular (LTE-M / NB-IoT) to the OEM
cloud over TLS mutual auth with RSA-2048 client certs.

### 4. Clinician-cloud access (clinical-decision portal)
The cardiology clinic accesses the OEM's remote-monitoring
portal via SSO federation (SAML RSA-SHA256) or via smart-card /
SMART-on-FHIR JWT RS256. EHR integration (Epic, Cerner/Oracle
Health) rides the same trust plane.

### 5. OTA firmware-update remote-trigger
Post-recall the industry moved toward remotely-triggered
firmware updates. FDA guidance (2018 Premarket Cybersecurity,
2023 Refuse-to-Accept Policy Section 524B) requires OEMs to
sustain signing infrastructure throughout device lifetime
(10+ years).

### 6. Adjacent pumps / continuous-glucose monitors / insulin
pumps follow an analogous pattern (Medtronic MiniMed 780G,
Tandem t:slim, Insulet Omnipod 5, Dexcom G7, Abbott FreeStyle).

## Regulatory anchors

- **FDA 21 CFR Part 820** quality system, 21 CFR 11 e-records
- **FDA 524B** cybersecurity (2023 statutory requirement)
- **AAMI TIR57**, **UL 2900-2-1** medical-device cybersecurity
- **ISO 27001 / ISO 13485 / IEC 62304 / IEC 62443-4-1**
- **EU MDR (2017/745)** + **MDCG 2019-16** security guidance

## Scale

- ~3M live patients with CIEDs; ~30M with any implanted
  networked medical device (including neuromodulation, pumps)
- Remote-monitoring transmissions: ~1 per day per patient ≈
  ~1 billion uploads/year globally
- A single implant's lifetime: 6–15 years; explant requires
  surgery

## Breakage

A factoring attack against:

- **An OEM implant firmware-signing root** (Medtronic, Abbott,
  BSci, Biotronik): signed firmware pushed remotely that
  delivers inappropriate shock (ICD), alters pacing thresholds,
  or disables bradycardia protection. Medical device cyber is
  among the most-studied attack surfaces (Halperin 2008, Rios
  + Butts 2018 multi-device). A cryptographically-valid malicious
  firmware represents loss-of-life capability at patient scale.
- **A programmer-pairing CA**: attacker mints a clinician-
  programmer credential, approaches an implanted patient within
  telemetry range, and reprograms the device in the wild. Not
  scalable, but targeted: diplomats, executives, dissidents.
- **A bedside-monitor client-CA**: forge or suppress remote-
  follow-up uploads. Silent suppression of arrhythmia events
  leading to undetected life-threatening rhythms. Forged
  uploads could drive false clinical interventions (inappropriate
  reprogramming visits).
- **Remote-trigger OTA root**: the industry's shift to remote
  firmware push becomes the vector — millions of devices
  updated within days.

CIED lifecycle is 6–15 years *in vivo*. A fleet firmware-signing-
root compromise means every patient needs a clinic visit for a
validated re-load, or — if that path is unavailable — explant
and re-implant (open surgery). FDA recall history shows this
process takes years per affected model.
