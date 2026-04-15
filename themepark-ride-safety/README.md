# Theme-park ride safety — signed PLC firmware, restraint-check
# chain-of-trust, show-control / dispatch authenticated messaging

Major theme-park operators (Disney, Universal, Six Flags, Cedar
Fair, Merlin / Legoland, OCT Chimelong, SeaWorld) run roller
coasters, dark rides, and large-scale water attractions under
**ASTM F24** (in particular F2291 design, F1193 operation, F770
inspection) and **EN 13814** (Europe). Each attraction's control
stack is a multi-layer PLC system:

- **Show controller** (ride sequence, media cues, animatronics)
- **Ride controller** (train dispatch, block logic)
- **Restraint monitoring** (harness latch sensors, over-shoulder /
  lap-bar position)
- **Safety PLC** (block-zone interlocks, e-stop distribution,
  anti-rollback, evacuation-position logic)

Vendors: **Siemens SIMATIC**, **Rockwell ControlLogix + GuardLogix**,
**Beckhoff TwinCAT Safety**, **Pilz PNOZmulti**, **B&R X20 SafeLOGIC**.
Attraction design: **Mack Rides**, **Intamin**, **B&M (Bolliger &
Mabillard)**, **Vekoma**, **RMC (Rocky Mountain Construction)**,
**Dynamic Attractions**, **ETF Ride Systems**, **Dynamic Structures**.

## RSA usage

### 1. Ride + safety PLC firmware signing
Same PLC families as the wind-turbine / ski-lift / refinery
safety use — Siemens F-CPU signed firmware, Rockwell GuardLogix
signed add-on instructions, Beckhoff TwinCAT TcSafety. Ride
integrators additionally sign a counter-manifest binding the
firmware set to a specific attraction installation.

### 2. Block-section / train-dispatch signed messages
Ride controller issues signed dispatch permissions to train
controllers — "Train 3 may leave station block", "Train 1 clear
of brake zone B". Both sides verify origin authenticity.

### 3. Restraint-check authenticated telemetry
Per-train per-seat restraint sensors (Hall-effect harness
latches, bar-position encoders) stream signed payloads to the
ride controller. A "restraint secure" signal is the gate to
dispatch — signature prevents injected "all-green" that could
mask an unfastened harness.

### 4. Show-control + animatronic chain
Show controllers (Alcorn McBride, Medialon, Gilderfluke, Dataton
Watchout, 7thSense Delta) sign cue sequences delivered to local
media servers, animatronic controllers, and dimmer/DMX nodes.
Integrity matters where cue mis-timing can harm guests (e.g.
pyrotechnic + water-effect + ride-motion synchronisation).

### 5. Remote vendor-support / condition-monitoring
OEM remote-support (Intamin Remote Assistance, Mack Rides 24/7,
Vekoma @ Care) uses TLS mutual auth with per-installation
RSA certs. Typically read-only; write actions gated on local
operator dual-control.

### 6. Regulator inspection e-signatures
Annual / state-inspection records (Florida DACS, California
OSHA Division of Ride & Tramway Safety, German TÜV) are digitally
signed by the authorised inspector.

## Scale + stickiness

- ~4,500 large amusement rides worldwide under ASTM F24 / EN 13814
- US theme-park attendance: ~370M/year
- Incidents: rare but high-consequence and heavily litigated
- Equipment lifecycle: 20–40 years (many coasters from the 1980s
  still operating on modernised control systems)
- Re-certification after any crypto change: engineering-of-record
  re-review, state approval, vendor QA — 6–18 months per ride

## Breakage

- **PLC vendor root factored** (Siemens / Rockwell / Beckhoff /
  Pilz): signed firmware disabling restraint-latch interlocks
  or allowing dispatch into an occupied block. Mass-casualty
  scenarios on inverted / launched coasters + water rides.
- **Ride-integrator signing root factored**: fleet-wide
  modification of the binding between firmware and installation
  permits OEM-approved-looking changes that invalidate the
  commissioning safety case.
- **Restraint-telemetry signing root factored**: "all secure"
  signal forged — trains dispatch with unfastened harnesses.
  The Schlitterbahn "Verrückt" 2016 fatality and several coaster-
  ejection incidents motivate this exact threat model.
- **Show-control signing root factored**: fireworks / water
  effects / ride motion desynchronised; guest burns, drownings,
  pyrotechnic injury.
