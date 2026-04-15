# Submarine fibre cable SLTE + repeater EMS — signed controller
# firmware, trans-ocean management authentication

**~99% of inter-continental internet traffic moves over submarine
fibre-optic cables** — ~550 cables, ~1.5 million km of fibre,
~$20B+ cumulative capex. Every cable has:

- **Wet plant**: repeaters every 40-100 km (amplifier pumps,
  dispersion compensation), branching units (BUs), fibre lines
- **Dry plant**: Submarine Line Terminal Equipment (SLTE) at each
  landing station — DWDM wavelength-division-multiplexing
  transponders doing coherent 100G/400G/800G modulation
- **NMS / EMS**: vendor-specific Element Management Systems that
  poll repeaters and configure SLTE

## Vendors + operators

- **SLTE**: SubCom (ex-TE SubCom), Alcatel Submarine Networks
  (ASN, Nokia), NEC, HMN Technologies (ex-Huawei Marine),
  Ciena GeoMesh Extreme, Infinera ICE6, Nokia 1830 PSI-M
- **Cable owners/consortia**: major hyperscalers (Google, Meta,
  Microsoft, Amazon direct-invest ~50% of new cables), traditional
  telcos (Tata, Telxius/Telefónica, Orange, NTT, KDDI, SingTel),
  sovereign entities

## RSA usage

### 1. SLTE / NMS firmware signing
Every SLTE chassis (SubCom C100, ASN 1620 LM, NEC SpaNet, Ciena
6500) boots signed firmware. Field software loads (FSUs) carry
RSA sigs validated by onboard bootloader.

### 2. EMS ↔ NOC authentication
Vendor EMS software (ASN EMS, SubCom TSM, NEC SpaNet SVN) sits in
the landing-station DC and communicates with vendor NOC over
mutually-authenticated TLS. Consortium members authenticate to the
EMS via RSA-backed SSO.

### 3. Wet-plant command authentication
Commands to wet-plant elements (repeater pump adjustment,
branching-unit state changes, line-monitoring-system queries) are
issued from the EMS and authenticated. Branching units can route
traffic to different landings — a high-value target.

### 4. Line Monitoring System (LMS) / COTDR signed measurements
High-Loss Loopback, Submarine Line Monitoring, Coherent OTDR
trace signatures bind each measurement to the emitting SLTE. Used
to localise cable faults to sub-km accuracy; also forms the
evidence basis for insurance claims (cable-cut incidents run
~$10-100M per repair) and sovereignty / damage-attribution
analysis.

### 5. Consortium operations + routing change authorisation
Cables are often owned by 10+ party consortia. Provisioning
changes — wavelength lighting, capacity transfer — are signed by
the consortium governance process over RSA-certified interfaces.

## Scale + stickiness

- ~550 submarine cables in service; ~80 new cables / year
- Single Atlantic / Pacific cable: $300M-$800M build, ~25-year
  design life
- 2022 Tonga cable cut disconnected a nation for 38 days
- 2024 Red Sea / Baltic cuts demonstrated cable-sabotage
  feasibility

Why RSA is sticky: wet-plant repeater firmware is not field-
updateable without a cable ship (cable-repair vessels cost
~$500,000/day and are booked months out). SLTE installed base
has 20-year amortisation. Once a signing chain is deployed, it
stays.

## Breakage

- **Vendor SLTE firmware root factored**: signed firmware that
  corrupts OSNR / FEC margin or mis-tunes pump lasers. Traffic
  failure at scale. Worst case: coordinated cross-cable attack
  simultaneously degrades multiple landings — global internet
  throughput drops dramatically (few spare cables for major
  regions).
- **Wet-plant command signing root factored**: branching-unit
  re-routing against consortium authorisation; traffic from
  one landing silently crossed to attacker-controlled taps.
  SIGINT at trans-ocean scale.
- **EMS ↔ NOC CA factored**: remote management of landing
  stations from attacker infrastructure.
- **LMS signing root factored**: forged fault localisation;
  cable cuts mis-attributed (insurance fraud, state-actor
  attribution reversed).

Wet-plant firmware rotation requires cable-ship recovery of
repeaters — tens-of-millions-of-dollars per cable.
