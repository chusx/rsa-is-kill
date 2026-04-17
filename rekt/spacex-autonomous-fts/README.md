# Autonomous Flight Termination / Safety Systems — signed
# command-destruct and range-safety state for expendable + reusable
# launch vehicles

Every orbital-class launch vehicle carries a **Flight Termination
System (FTS)** that can destroy the vehicle in flight if it deviates
from a safe corridor. Historically FTS was a UHF-commanded
destruct receiver operated by Air Force range safety officers. Modern
vehicles use **Autonomous Flight Safety Systems (AFSS)** — SpaceX
Falcon 9 / Falcon Heavy / Starship, ULA Vulcan, Rocket Lab Neutron,
Blue Origin New Glenn, Relativity Terran R all fly AFSS.

AFSS is governed by:
- **RCC 319-19 / 324** (US Range Commanders Council Flight
  Termination System Commonality Standard)
- **AFSPCMAN 91-710 V7** (Eastern/Western Range safety)
- **FAA Part 417 Appendix D** (commercial launch flight safety)

## RSA usage

### 1. Destruct command authentication
Legacy systems used NSA-Type-1 symmetric keying (HAIPE-class). AFSS
specifications (RCC 319-19 §9) permit asymmetric command
authentication for the command-destruct uplink path; vehicle-loaded
AFSS units verify destruct / abort commands against a range public
key. SpaceX operates an AFSS that is entirely autonomous (onboard
decision logic keyed to the vehicle's IIP), but the vehicle still
accepts a signed arm/disarm command from the range.

### 2. AFSS flight software signing
The AFSS processor (two-out-of-three redundant, radiation-hardened,
independently developed) loads mission-specific flight rules — a
corridor polygon, gate set, impact-limit lines — before every
launch. The corridor-load file is RSA-signed by range-safety
engineering. The AFSS refuses to arm without a valid signature on
the mission load.

### 3. Telemetry / IIP (Instantaneous Impact Point) downlink
IIP telemetry to the range control centre rides mutually-
authenticated TLS. Range Safety Officers watch a monitor fed by
cryptographically-authenticated state.

### 4. Ground command station chain-of-trust
The range Command Destruct Transmitter (CDT) signs outbound commands
with an HSM-held key. Key ceremony and dual-custody custody match
DoD KMI practice; public counterparts are burned into each vehicle
AFSS at factory integration.

### 5. Payload safing commands (secondary)
Many payloads — GPS III satellites, NRO birds, DoD ESPA rideshares
— have a separate command crypto plane from the vehicle bus. On the
commercial side (Starlink, Planet, Iridium NEXT) payload command
auth uses RSA-over-TLS mutual auth to the operator ground network.

## Scale

- ~200 orbital launches/year globally (2024, up from ~100 in 2020)
- SpaceX alone: ~130+ launches/year, every one AFSS-governed
- Eastern Range + Western Range + Wallops + Kodiak + Boca Chica +
  Cape Canaveral SLC / Vandenberg SLC — ~10 active launch complexes
  in the US
- Every launch involves an AFSS arm sequence that verifies a signed
  mission load

## Safety criticality

AFSS is the **last line of defense** preventing a malfunctioning
rocket from impacting a populated area. A Falcon 9 first stage
carries ~400 t of propellant; a Starship superheavy ~3,600 t. A
spurious or suppressed destruct command at the wrong moment is
a mass-casualty event — or, if destruct is triggered maliciously
on a nominal flight, the loss of a ~$70M+ vehicle and its
payload (which may carry 50+ Starlink satellites, crew, or NRO
assets).

## Breakage

A factoring attack against:

- **A range command-destruct signing key**: attacker issues a
  signed **destruct command** to a vehicle in flight from a
  rogue transmitter. Result: loss of vehicle, crew fatalities
  if crewed, debris over populated area if the vehicle is past
  the population-clear corridor gate.
- **An AFSS mission-load signing key**: attacker swaps the
  corridor polygon for a wider one before launch, allowing a
  deviated vehicle to reach land before autonomous destruct;
  or swaps for a narrower one, causing autonomous destruct on
  a nominal flight.
- **An AFSS flight-software root**: the processor accepts a
  malicious load that disables autonomous destruct logic
  entirely. A subsequent deviated flight impacts populated
  area.
- **A payload command-auth root**: satellite operator loses
  control of an in-orbit constellation — commanding a
  deorbit burn, or manoeuvring a spacecraft into another
  operator's asset. Kessler-risk if the fleet is in LEO.

Vehicle qualification timelines are 3–7 years. Range-safety
re-certification after key compromise requires FAA Part 450 / 417
re-verification of every vehicle's AFSS build — a multi-year
programme with launch cadence implications for the entire US
commercial space sector.
