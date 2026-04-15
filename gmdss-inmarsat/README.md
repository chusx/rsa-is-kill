# GMDSS / Inmarsat-C SafetyNET — authenticated maritime safety broadcasts

The **Global Maritime Distress and Safety System (GMDSS)**, mandated by
the IMO under SOLAS Chapter IV, requires every SOLAS vessel (~60,000
ships plus tens of thousands of non-SOLAS but voluntarily-fitted craft)
to carry a satellite terminal capable of receiving **Maritime Safety
Information (MSI)**: navigational warnings, meteorological warnings,
search-and-rescue information, piracy alerts.

The long-standing MSI bearer is **Inmarsat-C SafetyNET** (now
SafetyNET II alongside **Iridium SafetyCast** since 2020, under the
IMO-recognised-mobile-satellite-service regime). Terminals: JRC
JUE-87/95, Furuno Felcom-19, Sailor 6110, Thrane & Thrane TT-3000SSA.

## RSA usage

### 1. EGC (Enhanced Group Call) message authentication
SafetyNET II wraps each broadcast in an **authenticated envelope** —
the NAVAREA coordinator / METAREA meteo office / RCC signs the message
with an RSA key; the vessel terminal verifies against an IMO-published
trust list stored in the terminal's firmware. Legacy SafetyNET I
lacked cryptographic authentication; the 2020 upgrade added it
following spoofing concerns raised by IMO MSC.

### 2. Terminal firmware signing
The Inmarsat-C / FleetBroadband / Fleet Xpress terminal vendors ship
signed firmware (Cobham, JRC, Furuno, Thrane). Type-approval under
IMO Resolution A.807/A.1001 includes a cryptographic-integrity
requirement for the firmware path.

### 3. LRIT (Long-Range Identification and Tracking) position reports
SOLAS vessels transmit 6-hourly position reports to their flag
administration's LRIT data centre over TLS (client-cert per vessel).
The IMO International LRIT Data Exchange routes between DCs using
mutually-authenticated TLS.

### 4. ECDIS chart update signing
Electronic Chart Display and Information Systems (ECDIS, mandatory
under SOLAS V/19) consume IHO S-63 encrypted ENCs. S-63 Edition 1.2
uses an RSA-based scheme: the HO (UKHO, NOAA, SHOM, JHOD) signs
cell-permit files; the ECDIS verifies against the IHO Scheme
Administrator (SA) public key before decrypting the chart.

### 5. AIS message authentication (emerging — VDES)
Legacy AIS is unsigned; the successor **VDES (VHF Data Exchange
System)** under ITU-R M.2092-1 / IALA G1117 adds per-message
authentication using RSA/ECDSA signatures. Deployment is in rollout
(2024–2028) across coastal states.

## Scale

- ~60,000 SOLAS vessels worldwide
- ~700,000 Inmarsat / Iridium maritime terminals including non-SOLAS
- 21 NAVAREAs × ~20 MSI broadcasts/day globally
- IHO S-63 serves every ECDIS on the planet (~50k installations)

## Breakage

A factoring attack against:

- **The SafetyNET II MSI signing root / NAVAREA coordinator key**:
  attacker broadcasts a signed **false navigational warning** —
  fake minefield in the Strait of Hormuz, fake piracy alert diverting
  convoys, fake tsunami warning clearing a port. Ship masters are
  legally obliged under SOLAS to treat authenticated MSI as
  actionable; mass-diversion of commercial shipping is plausible.
- **An IHO S-63 Scheme Administrator key**: attacker distributes
  tampered ENC cells — charts with shifted shoal positions,
  erased rocks, modified traffic-separation schemes. ECDIS will
  display the forgery as authenticated. Groundings likely on
  vessels trusting the display.
- **An LRIT DC TLS root**: fabricated position reports to / from
  flag administrations. Sanctions enforcement (OFAC, UN panel
  monitoring) uses LRIT as evidence; integrity collapse.
- **A terminal firmware root (Cobham/JRC/Furuno)**: brick or
  silently mute GMDSS terminals across a fleet; a distress alert
  from a sinking vessel never reaches the RCC.

Maritime terminal lifecycles are 15–25 years. Firmware-root
compromise means dry-dock visits for tens of thousands of hulls.
Chart-signing-root compromise means IHO must re-issue the weekly
update cycle under a new key to 50k ECDIS installations via
DVD/USB (many vessels still don't have broadband).
