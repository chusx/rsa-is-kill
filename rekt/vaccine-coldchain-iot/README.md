# Vaccine + biologics cold-chain IoT — signed temperature logs,
# GDP / VAWD traceability, UNICEF / WHO distribution

Vaccines, monoclonal antibodies, cell therapies, and other
biologics require **cold-chain custody between +2°C and +8°C**
(some Pfizer/BioNTech mRNA: –80°C; Moderna: –20°C). Any excursion
must be documented; many excursions render a lot unusable.

## Supply chain

- **Manufacturers**: Pfizer, Moderna, GSK, Sanofi, Merck,
  AstraZeneca, Serum Institute of India, BioNTech, Novavax,
  CSL Behring, Novartis (cell therapy Kymriah), Gilead (Yescarta)
- **Logistics**: FedEx Custom Critical, DHL Life Sciences, UPS
  Healthcare (Marken), Kuehne+Nagel KN PharmaChain, Cavalier
  Logistics, World Courier, Yusen Tower, Lufthansa CargoFresh
  / Envirotainer / va-Q-tec containers
- **Cold-chain data loggers**: Sensitech (Carrier), ELPRO,
  LogTag, ORBCOMM, Berlinger, Controlant (Pfizer COVID-19
  contract), DeltaTrak, Temptime (HEATmarker VVM for WHO EPI)
- **Distribution / GDP**: McKesson, Cardinal Health, AmerisourceBergen
  (Cencora), Movianto, GSK OneDoor, UNICEF Supply Division,
  PAHO Revolving Fund, Gavi
- **Clinical-site integration**: FHIR + IIS (Immunization
  Information Systems — state registries + CDC IZ Gateway)

## RSA usage

### 1. Data-logger firmware + per-device cert
Every cold-chain logger ships with RSA-signed firmware and a per-
unit cert used to sign temperature logs at the end of each
shipment. The signed log is the evidentiary artefact that
determines whether the lot can be dispensed.

### 2. Shipment-envelope signing (GDP / GxP / ALCOA+)
Manufacturer → wholesaler → pharmacy / clinic hand-offs carry
signed "dispatch-receipt" records under EU GDP 2013/C 343/01,
USP <1079>, WHO TRS 961 Annex 9. Lot number + NDC / GTIN + DSCSA
T3 data are bound in signed EPCIS events (cross-ref
`dscsa-pharma-serialization/`).

### 3. IIS reporting signing (US CDC IZ Gateway)
Administered-dose records flow from clinic / pharmacy → state
Immunization Information System → CDC IZ Gateway over HL7
v2.5.1 or FHIR. Federated trust via NwHIN / DirectTrust RSA
certs.

### 4. WHO / UNICEF programme integrity
The WHO Expanded Programme on Immunisation (EPI) plus Gavi
campaigns sign allocation manifests to recipient countries.
Per-consignment RSA signatures bind lot → campaign → destination.

### 5. Temperature-excursion adjudication
Insurance claims for excursion-damaged lots (~$100M+/year
globally) depend on signed logger traces as evidence. Logger-
vendor CA is the trust anchor.

### 6. DSCSA / FMD serialisation overlap
US DSCSA T3 (2024) and EU FMD (2019) shift packs under signed
serialisation. Cold-chain signed logs layer on top: both
provenance and in-transit conditions proven cryptographically.

## Scale + stickiness

- Global vaccine doses annually: ~5 billion (routine + campaigns)
- Cell + gene therapy shipments: per-patient, individually
  irreplaceable (autologous CAR-T)
- Data loggers in service: ~500 million single-use + >10 million
  reusable
- Deep-frozen cell-therapy shipments per year: ~25,000 with
  doses valued at $400k–$3M each

Why RSA stays: vendor logger firmware is resource-constrained
(MSP430 / low-power Cortex-M0). Factory-burned certs. FDA-
registered software. Migration roadmaps aren't budgeted at
logger-OEM or wholesale-distribution level.

## Breakage

- **Logger-vendor CA factored** (Sensitech / ELPRO / Controlant /
  Berlinger): attacker signs forged temperature traces — lots
  actually excursion-damaged appear pristine and are dispensed;
  or pristine lots appear damaged and are destroyed (supply
  attack during a pandemic).
- **Manufacturer dispatch-receipt signing root**: counterfeit
  "pedigree" on grey-market product. Contaminated / expired /
  counterfeit biologics enter legitimate pharmacy shelves.
- **IIS / CDC IZ Gateway CA factored**: forged administered-dose
  records; public-health herd-immunity statistics corrupted;
  individuals falsely recorded as vaccinated (or not).
- **UNICEF / Gavi consignment CA factored**: shipment diversion
  against sanctioned or fragile-state recipients; humanitarian
  supply disrupted during crisis.
