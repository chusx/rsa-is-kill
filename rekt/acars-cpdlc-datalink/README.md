# Aviation ACARS + CPDLC datalink — ARINC 823 AMS + FANS 1/A+
# signed controller-pilot messages

Civil aviation is migrating voice ATC → **datalink**. Two parallel
stacks: **ACARS** (airline-ops messaging, fuel, OOOI, weather,
maintenance) + **CPDLC** (Controller-Pilot Data Link Comms — the
ATC channel). Under **ARINC 823 AMS (ACARS Message Security)** +
the emerging **FANS 1/A+ with integrity**, datalink messages carry
RSA signatures binding originator to content. Oceanic + polar +
remote-airspace ATC is already datalink-primary (no VHF coverage).

## Players

- **CSPs (Communications Service Providers)**: SITA, ARINC /
  Collins Aerospace (Rockwell), Inmarsat SwiftBroadband Safety,
  Iridium Certus (NBAA), Viasat (Airbus Connect)
- **Avionics vendors**: Collins Aerospace (TDR-94, CMU-4000),
  Honeywell (MCS-7000 Satcom, ACARS MCDU), Thales (TopWings),
  GE Aviation FMS, Universal Avionics
- **ANSPs**: FAA + Data Comm (CPDLC en-route), NAV CANADA, UK
  NATS, DFS Deutsche Flugsicherung, DSNA France, EUROCONTROL
  MUAC, Airservices Australia, ICAO CRA-operated OCA datalink
- **Airlines**: all 737 MAX / 787 / A320neo / A350 / 777X built
  since 2010 include FANS 1/A+ by default; retrofits across
  widebody widebody fleet

## RSA usage

### 1. ARINC 823 AMS signed ACARS messages
Downlink ACARS messages (position reports, flight-plan requests,
maintenance CBIT reports, fuel-on-board, ETA updates) are AMS-
signed by the CMU / ATSU RSA key. Ground systems verify before
accepting into airline ops or flight-following.

### 2. CPDLC message integrity
FANS 1/A+ CPDLC message integrity (still being standardised into
SESAR + NextGen Data Comm Segment 2) envelopes controller uplinks
(altitude change, route amendment) with signatures so the aircraft
verifies origin before pilot Accept/Reject.

### 3. Loadable-software-airworthiness (LSAP) signing
Avionics software parts (ARINC 665 data files — FMS nav database,
engine EICAS files, cabin-comms images) are signed under **DO-326A
/ ED-202A** airworthiness security. Aircraft refuses unsigned
LSAP load on ground via aircraft-data-loader.

### 4. AOC / airline-ops PKI
Airline-ops messages (SITA Type-B migration to Type-X, flight
release, dispatch releases, weight-and-balance finalisation) are
signed by the airline's dispatch credential; captain's signed
acceptance closes the pre-departure legal release.

### 5. NOTAM + MET + ATIS-D digital signing
Digital NOTAMs (FAA SWIM, EUROCONTROL NOF), METAR/TAF, and
ATIS-D are signed at source. Aircraft EFB / avionics verify
before display to pilot.

## Scale + stickiness

- Western-built commercial aircraft in service: ~25,000 with
  CPDLC-capable avionics
- Daily CPDLC messages worldwide: millions
- Cert rotation requires flight-division engineering change (type-
  cert amendment) at OEM — Boeing / Airbus MCC coordination
- DO-326A airworthiness-security certification assumes specific
  crypto — recert through FAA AC 20-170 / EASA AMC 20-42

Why RSA stays: avionics service life is 25-30 years. ARINC 823
AMS, ARINC 664 AFDX crypto profiles, and DO-326A were ratified
with RSA. A migration needs RTCA SC-216 + EUROCAE WG-72 joint
revisions, followed by type-certificate re-evaluation at each
OEM. No commercial airline has budgeted a post-quantum avionics
refresh.

## Breakage

- **Avionics OEM LSAP signing root factored** (Collins / Honeywell
  / Thales / Boeing / Airbus): forged nav databases or engine
  parameter files load onto aircraft — unsafe approach waypoints,
  wrong V-speeds, mis-tuned engines. DO-326A airworthiness case
  collapses fleet-wide.
- **ANSP CPDLC signing root factored**: forged controller
  instructions accepted by aircraft — altitude deviations, route
  amendments, or forged "cleared to land" / "go around" events
  in terminal airspace.
- **Airline AOC dispatch root factored**: forged dispatch
  releases, forged W&B; flights legally-undispatched yet
  apparently-released.
- **NOTAM / MET signing root factored**: forged NOTAMs creating
  phantom airspace restrictions, or concealing real ones;
  mis-briefed flights.
