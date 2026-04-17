# Link 16 / MIDS — NATO tactical data link crypto-key provisioning

**Link 16** (MIL-STD-6016, STANAG 5516) is the NATO tactical data
link connecting fighter aircraft, AWACS, ships, ground air-defence,
and C2 nodes. It moves track data, engagement assignments, and
identification information in real time. Crypto: symmetric
(COMSEC + TRANSEC at the waveform layer) but **key provisioning,
terminal certification, and mission-plan distribution ride an
RSA-based PKI** operated by NSA-equivalent entities per nation.

## Terminals + scope

- **MIDS-LVT / MIDS-JTRS / MIDS-ON-SHIP** — multi-function
  waveform terminals on F-15, F-16, F/A-18, F-22, F-35, Eurofighter
  Typhoon, Rafale, Gripen, Tornado; DDG / CG / LHA / LHD / CVN ships;
  Patriot, THAAD, NASAMS air-defence nodes
- **JREAP** (Joint Range Extension Application Protocol) — Link 16
  over IP for bandwidth beyond line-of-sight; carries its own
  authenticated envelope

Vendors: Data Link Solutions (DLS — Collins + BAE JV), ViaSat,
Thales, Leonardo (Italy), Indra (Spain), Rockwell Collins.

## RSA usage

### 1. Terminal Electronic Crypto Unit (ECU) firmware signing
MIDS ECU firmware updates go through NSA COMSEC Material Control
System (CMCS) with RSA-signed bundles. Terminal refuses
unsigned + chain-broken loads.

### 2. COMSEC key loading identity
Keys are physically loaded from a fill device (KIK-20 / SKL /
NGLD-M). The SKL itself authenticates to a **key-management
facility (KMF)** over an RSA-chained session before fills are
released. Over-the-air rekey (OTAR) paths on newer MIDS-JTRS / 
Link 22 blocks use an RSA-authenticated envelope around the
symmetric keys.

### 3. Network enterprise time / position signing
GPS M-code + SAASM terminals rely on a signed **almanac /
keying chain** that binds the terminal to the GPS control
segment; this is separately covered in `galileo-osnma/` for the
civil side but the military equivalent is similarly RSA-anchored
at the ground-segment signing level.

### 4. Mission-plan / MDL (Message Definition Library) signing
Mission data files loaded onto aircraft (Load Sets — DTC on F-18,
PMDS on F-16, PMDL on F-35) carry RSA signatures chaining to the
service's mission-planning PKI. Flight-computer refuses unsigned
mission loads.

### 5. Cross-domain guard PKI
Multi-national coalition operations route Link 16 via cross-
domain guards (Forcepoint High Speed Guard, Owl Cyber DualDiode).
These guards authenticate with RSA.

## Scale + stickiness

- ~10,000 Link 16 terminals across NATO + partners
- Every 4th-gen + 5th-gen Western fighter carries one
- Platform lifecycle: 30–40 years (F-16 entered 1978 and will fly
  into 2040s; B-52 originally 1955 and flying into 2050s)

Why RSA stays: NSA Suite B mandated ECC for public information
but **mission-system crypto cert hierarchies remain RSA** through
the current CNSA 2.0 transition plan, with the PQ roadmap
pointing at ML-DSA rather than ECDSA for tactical systems. Legacy
terminal installed base cannot be flashed in the field without
truck-roll per aircraft.

## Breakage

- **KMF provisioning root factored**: attacker mints look-alike
  SKL / KMF credentials, arranges fills of attacker-controlled
  keys into an isolated terminal; with that in place the
  waveform keys themselves are exfiltrated. Result: **real-time
  SIGINT on NATO tactical data link**. Force-composition,
  engagement assignments, and IFF state visible to the
  adversary.
- **Terminal firmware root factored**: NSA-signed firmware that
  silently degrades COMSEC entropy or leaks traffic-key indices.
  Fleet-wide compromise of every aircraft carrying a MIDS
  terminal from that vendor.
- **Mission-plan signing root factored**: attacker delivers
  signed mission loads that alter ROE-relevant inputs (no-strike
  coordinates, IFF responder codes, jammer profiles). Blue-on-
  blue risk during active operations.
- **Cross-domain guard root factored**: coalition data-sharing
  channels (US ↔ NATO Partner) integrity lost; espionage via
  injected/altered tracks.

A cryptographic rotation touches every airframe in every NATO
service. Even the routine key-crypto-period roll is a major
logistical effort; a factoring-break rotation of the RSA
hierarchy is a multi-year fleet-wide programme conducted under
wartime or near-wartime conditions.
