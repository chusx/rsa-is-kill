# EV charging Plug-and-Charge — ISO 15118-2 / -20 + V2G PKI

**ISO 15118 Plug-and-Charge (PnC)** lets an EV automatically
authenticate + authorise itself to any compatible charger without
driver interaction (no RFID, no app). The trust fabric is the
**V2G PKI**: **V2G Root CA** → OEM Provisioning CA + Mobility-
Operator Sub-CA + Charge-Point-Operator Sub-CA + Certificate
Provisioning Service. ISO 15118-2 (2014) **mandates RSA-2048**
for signatures; ISO 15118-20 (2022) adds ECC but backward
compatibility requires charging stations to continue supporting
RSA for -2 vehicles indefinitely.

## Players

- **V2G Root operator**: Hubject (OICP / OCA intercharge roaming)
  — the dominant root; VW Group, BMW, Ford, Mercedes all enrolled
- **EV OEMs** (contract cert installers): Volkswagen Group, Ford,
  Porsche, Hyundai-Kia, Mercedes, BMW, Volvo, Polestar, Tesla (NACS
  + ISO 15118 harmonisation pending)
- **Charger vendors**: ABB Terra HP, ChargePoint Express, Tritium
  PK350, Alpitronic Hypercharger, Siemens Sicharge, Tesla
  Supercharger V3/V4
- **Mobility Operators**: EnBW, Ionity, Electrify America, BP
  Pulse, Shell Recharge, TotalEnergies, Fastned
- **Regulatory**: EU AFIR (Alternative Fuels Infrastructure
  Regulation 2023/1804), US NEVI program

## RSA usage

### 1. Contract-certificate installation (CertificateInstallationReq)
When a vehicle first plugs in, the OEM Provisioning CA issues a
signed contract certificate binding vehicle VIN to mobility
operator account. Signed under RSA-2048 for ISO 15118-2 cars.

### 2. SessionSetup + AuthorizationReq signing
Each TLS-inside-PLC-PLC session between EVCC (vehicle) and SECC
(charger) uses mutual TLS with RSA 2048 certificates. The
AuthorizationReq carries the contract cert + PSS signature over
GenChallenge.

### 3. Metering-receipt signing (AFIR + German EichR compliance)
German **Eichrecht** (calibration law) requires the charger to
sign each metering receipt — the signed receipt is the evidentiary
artefact for billing disputes + consumer protection. AFIR extends
similar requirements EU-wide from 2024.

### 4. Charge-schedule signing (V2G / V1G flex)
When vehicles participate in grid-services (V2G: bidirectional,
V1G: smart-charging), schedules exchanged with the aggregator
carry RSA signatures. Settlement depends on signed commitments.

### 5. OCPP-to-backend charger ↔ CSMS signing
Charger → Central System (OCPP 2.0.1 + OCPP Security Profile 3)
uses RSA-certificate mutual TLS. Firmware update notifications
are RSA-signed by charger OEM.

## Scale + stickiness

- Global public chargers: ~4 million (2026); projected 15M by 2030
- EVs in service supporting ISO 15118-2 (RSA): every European EV
  from model-year ~2019 onward — tens of millions
- V2G PKI: millions of certs issued by Hubject alone
- Eichrecht-sealed chargers: ~500,000 in Germany + growing EU-wide

Why RSA stays: ISO 15118-2 vehicles on the road for 15+ years
demand back-compat. AFIR 2023/1804 references specific crypto
standards; any migration is a legislative re-amendment. Hubject
V2G Root is the de-facto roaming fabric for 30+ countries; rotation
touches every EV, every charger, every mobility contract.

## Breakage

- **V2G Root factored**: attacker impersonates any mobility
  operator or OEM. Fraudulent contract certs charge arbitrary
  vehicles against arbitrary accounts; chargers cannot
  distinguish legitimate roaming from impersonation.
- **OEM Provisioning CA factored**: forged contract certs for
  that OEM's entire fleet — mass charging-fraud attack,
  automaker liable under mobility-operator settlement rules.
- **Charger OCPP signing key factored**: rogue firmware loaded
  on vendor's fleet — pricing manipulation, billing fraud at
  scale, or deliberate sabotage of charger availability.
- **Metering-receipt key (Eichrecht sealed meter) factored**:
  consumer-protection evidentiary chain collapses; class-action
  billing disputes unresolvable.
