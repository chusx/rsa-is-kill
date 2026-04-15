# EU smart tachograph (Regulation 165/2014 + 2021/1228) —
# driver-card + vehicle-unit cryptographic chain

EU commercial-vehicle drivers' hours are enforced by a tamper-
resistant **digital tachograph** (VU = Vehicle Unit) bound to a
**driver smart card**. The Smart Tachograph Gen2v2 specification
adds per-minute location + authenticated DSRC remote-enforcement
readout. The whole stack is an EU-wide PKI: **ERCA** (European
Root CA, JRC Ispra) → **MSCA** (member-state CAs) → VU, driver
card, workshop card, company card, control card.

## Players

- **VU manufacturers**: Continental VDO DTCO 4.0 / 4.1, Stoneridge
  SE5000 Exakt DUO+, Intellic EFAS
- **Card personalisation (MSCA)**: Bundesdruckerei (DE), IMPRIMERIE
  NATIONALE (FR), Oberthur / IDEMIA (many MSCAs), Gemalto-Thales
- **ERCA operator**: European Commission Joint Research Centre,
  Ispra (IT)
- **Enforcement**: police roadside (control card), workshop
  technicians (workshop card), fleet operators (company card)
- **Legislation**: EC 165/2014 + EU 2021/1228 (Smart Tacho 2)

## RSA usage

### 1. Gen1 VU + cards — RSA-1024/2048 authentication
The Gen1 architecture (deployed since 2006, still in field) uses
**RSA** for card↔VU mutual authentication, digital signatures on
downloaded data (`.ddd` files), and certificate chain. Millions
of Gen1 VUs remain in service. Gen2 adds ECC but backward-
compatibility preserves RSA verification paths.

### 2. Driver-activity download signing
When fleet operators download driver activity every 28 days
(legal max period), the VU signs the `.ddd` file. Courts accept
the signed file as evidence in drivers'-hours prosecutions.

### 3. Workshop calibration signing
Workshop technicians use a **workshop card** to calibrate VU
parameters (tyre circumference, vehicle identification). The
calibration event is signed into the VU's internal event log —
tamper-evident against odometer fraud.

### 4. DSRC roadside remote early-detection
Gen2 VUs emit a DSRC 5.8 GHz authenticated "tachograph summary"
every ~60 s. Police roadside units verify the signature before
deciding whether to stop the vehicle — enables enforcement
without pulling over compliant trucks.

### 5. Company-card fleet integration
Fleet-management systems (TomTom WEBFLEET, Transics, Microlise,
Masternaut) ingest signed downloads at scale. Insurance claim
integrity + working-time directive compliance rest on signature
validity.

## Scale + stickiness

- ~6 million VUs in EU + Switzerland + UK fleets
- ~12 million active driver cards
- ~25,000 authorised workshops
- Average VU service life: 10-15 years
- Legal basis: EU Regulation 165/2014 — any crypto change needs
  Commission-level amendment

Why RSA stays: ERCA+MSCA is a treaty-level cryptographic
infrastructure. Changing algorithms means re-certifying every
VU manufacturer, re-issuing every card, republishing national
CA hierarchies across 30+ member states. Gen1 RSA continues to
be accepted under Article 3 transitional provisions.

## Breakage

- **ERCA root factored**: attacker issues forged MSCAs — fake
  driver/workshop/company cards accepted EU-wide. Driving-time
  enforcement collapses; haulier compliance unverifiable.
- **MSCA signing key factored**: per-member-state card cloning
  at scale (e.g. one driver → unlimited "rested" cards alternated
  to evade the 9-hour daily limit).
- **VU manufacturer signing key factored**: counterfeit VUs fitted
  with modified firmware reporting compliant hours regardless of
  actual driving. Grey-market installation via corrupt workshops.
- **Workshop card signing factored**: retroactive odometer +
  calibration rewrites — second-hand truck fraud + insurance
  attribution problems on accident reconstruction.
