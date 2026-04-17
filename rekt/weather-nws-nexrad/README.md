# NWS / EUMETSAT / JMA weather products — signed radar, satellite,
# and warning dissemination

National meteorological services produce warnings (tornado, hurricane
track, tsunami, severe thunderstorm, flash flood, winter storm,
volcanic ash advisory) that trigger automated public response:
**Wireless Emergency Alerts (WEA)**, EAS, siren activation,
aviation SIGMETs, maritime NAVTEX. Downstream consumers (TV /
radio / airlines / app providers / emergency managers) accept
products as authoritative based on cryptographic signatures over
the product stream.

## Players

- **Public producers**: NWS (NEXRAD, GOES-R, GFS, NBM, WPC, NHC,
  SPC, Tsunami Warning Centers), EUMETSAT (Meteosat Third
  Generation, MetOp-SG), JMA (Himawari-9), ECMWF, Météo-France,
  DWD, Met Office UK, BoM Australia, Env Canada
- **Dissemination**: NWS NOAAPort / SBN satellite, EMWIN,
  iNWS, NWSChat, NWS IEMBot, EUMETCast
- **Consumers**: broadcast media (ABC / NBC / CBS / BBC / NHK),
  aviation (airline dispatchers, ATC, EUROCONTROL MUAC), maritime
  SOLAS (GMDSS NAVTEX), emergency-management agencies, weather-
  app SDK vendors (AccuWeather, DTN, The Weather Company)
- **Relays**: FEMA IPAWS OPEN for WEA + EAS origination (ingests
  NWS-signed CAP); state-level warning points

## RSA usage

### 1. CAP 1.2 signed warning dissemination
NWS issues warnings as CAP 1.2 XML messages with XMLDSig RSA
signatures (NWS-CAP-v1.2). IPAWS OPEN verifies signature before
amplifying to cell carriers (WEA) + EAS + NOAA Weather Radio.

### 2. NEXRAD Level II / III product signing
NEXRAD RPG → Product Distribution signs Level II + III products
distributed via NOAAPort SBN + AWIPS TCP/IP. Broadcast / aviation /
research consumers verify signatures before accepting.

### 3. Tsunami bulletin signing (PTWC / NTWC)
Tsunami warning centres sign bulletins distributed via WMO GTS,
PacIOOS, IOC-UNESCO. Pacific rim emergency managers and
SOLAS maritime systems act on signed bulletins automatically.

### 4. SIGMET / AIRMET / Volcanic Ash Advisory signing
ICAO Annex 3 meteorological information for aviation — SIGMETs,
AIRMETs, volcanic-ash advisories (9 VAACs globally) are signed
before distribution via WAFS / OPMET. Airline dispatchers route-
plan against signed advisories.

### 5. FEMA IPAWS originator authorisation
FEMA IPAWS issues signing credentials to state + local + tribal
emergency managers. Each issued alert (WEA / EAS) carries the
originator's signature; FEMA's root is the WEA trust anchor for
cell carriers.

### 6. WMO Information System GTS product signing
WMO GTS + WIS 2.0 (Publish-Subscribe) signs bulletins at the
originating NMHS for authenticity across hundreds of national
hops.

## Scale + stickiness

- NWS warnings/year (all products): ~1.5 million
- WEA messages/year (US): ~5,000
- GTS bulletins/day globally: ~500,000
- NEXRAD radars: 160 US + 40 international (DoD + FAA-operated)
- Warning-dissemination refresh: IPAWS OPEN specification
  rev-locked; any crypto change needs carrier-side coordination

Why RSA stays: IPAWS OPEN IOP (Interoperability Profile)
baselines XMLDSig RSA. WMO GTS technical regulation freezes
bulletin integrity on an RSA profile negotiated by 193 member
states. ICAO Annex 3 + Annex 10 crypto-profile changes go
through state-level ICAO Council amendments.

## Breakage

- **NWS CAP signing root factored**: attacker issues forged
  WEA-eligible warnings — fake tsunami evacuation, fake tornado
  warning, triggering public panic + economic disruption. 2018
  Hawaii ballistic-missile false alarm demonstrated the human
  cost; a cryptographic compromise scales it.
- **FEMA IPAWS root factored**: all WEA / EAS authenticity
  collapses. Broadcasters face impossible choice — relay or
  drop all alerts pending federal reattestation.
- **VAAC / tsunami bulletin signing factored**: aviation and
  maritime SOLAS automated response chains break — wrong
  reroutes + wrong coastal evacuations.
- **WMO GTS bulletin signing factored**: international numerical-
  weather-prediction inputs corruptible; forecast-model quality
  degrades globally.
