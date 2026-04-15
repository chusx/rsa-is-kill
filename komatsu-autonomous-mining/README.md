# Komatsu FrontRunner / Caterpillar MineStar — autonomous haulage
# system command-and-control, signed dispatch and safe-stop

The world's largest open-pit mines run **autonomous haulage systems
(AHS)**: driverless 400-tonne-class haul trucks moving 24/7.
Dominant platforms:

- **Komatsu FrontRunner AHS** (~700 trucks deployed; Pilbara iron
  ore, Chilean copper, Canadian oil sands)
- **Caterpillar Cat® MineStar Command for hauling** (~500 trucks;
  Fortescue, BHP, Rio Tinto, Teck)
- **Hitachi Autonomous Haulage System** (~50 trucks)
- **Epiroc / Sandvik** autonomous underground loaders and drills

Behind the trucks: a **mine-planning and fleet-management system**
(Komatsu Modular DISPATCH, Cat MineStar Fleet, Hexagon MinePlan,
Deswik) issues signed dispatch missions to each truck, and a
**traffic-control / safe-stop** channel can command any vehicle to
a controlled halt.

## RSA usage

### 1. AHS truck firmware signing
The autonomous kit on each truck — vehicle controller, perception
(LIDAR + radar + camera), RTK-GNSS, cellular/mesh modem — runs
RSA-signed firmware images produced by the AHS vendor. A Komatsu
930E-AT / Cat 793F AT / Hitachi EH4000AC-3 with autonomy package
costs ~$5-7M each; there are 1,200+ in production at current fleets.

### 2. Mission / route / berm-file signing
Every dispatched haul cycle: pickup point, drop point, route
waypoints, max-speed profile, stop-exclusion zones (people,
manned equipment), dump-edge geometries — is authored in the
mine-office FMS and signed before transmission to the truck.
The truck's safety monitor refuses un-signed or stale (replayed)
missions.

### 3. Safe-stop / E-stop broadcast authentication
The mine-control tower can issue a **fleet-wide or per-vehicle
safe-stop** over a dedicated radio channel. This is the last-line
safety control when a pedestrian or manned vehicle enters the pit.
Commands are RSA-signed by the tower HSM; trucks verify before
actuating. The same channel carries speed-zone overrides (e.g.
"reduce to 15 km/h in zone 4 due to wet conditions").

### 4. Personnel proximity / collision-avoidance tokens
Each manned vehicle and each worker on foot in the pit carries a
Proximity Detection System (PDS, ISO 21815 / MSHA Prox regulation
coming). Token identity is bound to an RSA-signed credential that
the AHS trucks verify before treating that track as a human; this
prevents cheap RF spoofing from misclassifying cargo as workers
(denial-of-productivity) or from hiding workers from the trucks.

### 5. Mine cloud telemetry + OEM remote-support
Caterpillar VisionLink / Komatsu KOMTRAX / Hitachi ConSite stream
per-truck telemetry to the OEM backend over TLS mutual auth.
Per-asset RSA-2048 client certs.

### 6. Blast-control network signing
Mine blasting controllers (Orica, Dyno Nobel, BME) use signed
firing plans delivered to the electronic detonator initiators.
Misfire suppression, delay pattern integrity, and blast-exclusion
zone enforcement all ride crypto.

## Scale

- ~1,300 autonomous haul trucks globally (2024), 3× 2019 count
- Autonomous ore moved / year: ~5 Gt (>30% of global surface-
  mined ore)
- Single Pilbara iron-ore operation (Rio Tinto, BHP, FMG): ~250
  autonomous trucks each moving ~400 t/load, 24/7
- A fleet-wide autonomous outage at one major operation: ~$20M/day
  in deferred production

## Breakage

A factoring attack against:

- **Komatsu / Caterpillar AHS firmware root**: signed firmware
  pushed to the autonomy stack that subtly biases steering or
  disables collision-avoidance. At 64-tonne truck closing speeds,
  fatality risk for any manned vehicle or worker in the pit.
- **FMS mission-signing root**: attacker signs a mission routing
  a loaded truck off an unbermed edge (dump over-topple
  incidents have been historical fatality sources) or into an
  exclusion zone.
- **Mine-control safe-stop key**: attacker injects spurious
  safe-stops — denial of production, multi-$M/day — or, worse,
  signs a "cancel safe-stop" after legitimate emergency triggers.
- **Proximity-token signing root**: attacker mints forged PDS
  tokens so that legitimate workers' radios are distrusted while
  arbitrary decoys appear to be workers. Safety case collapses.
- **Blast-control signing root**: the potential for mis-timed
  blasts near manned equipment, or the suppression of legitimate
  misfire warnings before drill crews re-enter the blast area,
  is catastrophic.

Mining equipment lifecycles: 15–25 years. Fleet-wide firmware-
signing-key rotation requires physical access to every truck in
pit, scheduled around 24/7 operations — a years-long programme.
