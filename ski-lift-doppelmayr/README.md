# Cable car / gondola / ski-lift safety controllers — signed PLC
# firmware, signed ropeway-monitoring datalinks

Mountain ropeways — chairlifts, detachable gondolas, aerial trams,
pulsed gondolas, funiculars — are regulated under **EN 13243**
(Europe), **ASME B77.1 / B77.2** (North America), and Swiss
**SKUS / CenCenelec** standards. The ropeway installed base
worldwide is **~24,000 lifts in ski/tourism + ~3,000 in urban
cable-car transit** (Medellín, La Paz, Mexico City, Caracas,
Ankara, NYC Roosevelt Tram, Portland OHSU).

## Vendors

- **Doppelmayr / Garaventa** (Austria/Switzerland) — ~70% global
  share
- **Leitner / Poma / Agudio** (Italy/France) — ~25%
- **Bartholet Maschinenbau** (Swiss) — ~5%
- **Skytrac Tramways** (USA) — fixed-grip North American
- **MND Group / LST Ropeways** — specialist urban transit

## RSA usage

### 1. Drive + brake PLC firmware signing
Modern ropeway drive PLCs (Siemens SIMATIC S7 / Beckhoff
TwinCAT / Rockwell ControlLogix bundled by the ropeway OEM) ship
with signed firmware. Overspeed and emergency-brake logic lives
on a separate Safety-PLC (Siemens F-CPU / Pilz PNOZmulti) — each
with its own TÜV-certified signing chain.

### 2. Per-grip / chair monitoring telemetry
Detachable gondolas carry per-grip sensors (grip-force, door
latch state); new installs (2015+) run a wireless signed
telemetry uplink to the bottom station. Signatures bind the
reading to the grip unit identity.

### 3. Remote operator / manufacturer support
Vendor remote-service links (Doppelmayr CONNECT, Leitner Leitop)
terminate TLS-mutual on the drive cabinet. Client certs per
installation.

### 4. Seasonal inspection e-signing
Annual TÜV / federal inspection reports are digitally signed by
the inspector and counter-signed by the operator — RSA-backed.
The report is a regulatory precondition for seasonal operation.

### 5. Urban-transit SCADA integration
Urban ropeways integrate with city transport SCADA + ticketing
(Metrocable Medellín, Mi Teleférico La Paz). Authenticated
channels between lift SCADA and city transport authority.

## Scale + stickiness

- ~27,000 ropeways worldwide
- 350M+ annual skier days globally
- Urban-cable commuters: La Paz alone ~250,000/day
- Lifecycle: 25–40 years main structure, 10–20 years electronics

Why RSA is sticky: ropeway regulatory bodies (SKUS, TÜV, OITAF,
Transport Canada) certify each installation individually. Any
cryptographic-architecture change needs dossier re-review.
Installations in service since 2005 are not expected to migrate
before decommissioning.

## Breakage

- **Drive-PLC / brake-PLC firmware root factored** (Siemens,
  Beckhoff, Rockwell): signed firmware that disables overspeed
  protection or emergency-brake logic. Ropeway failures at
  terrain load produce mass-casualty events (Stresa-Mottarone
  2021: 14 fatalities from a single brake-system failure).
- **Vendor ropeway-controller signing root** (Doppelmayr,
  Leitner): fleet-wide mis-tuning of dynamic stopping distances,
  anti-rollback logic, wind-speed interlocks.
- **Per-grip telemetry root**: silent suppression of a failing
  grip warning before it ejects a chair.
- **Inspection e-signing root**: forged annual TÜV approval
  for a lift that should have been grounded.
