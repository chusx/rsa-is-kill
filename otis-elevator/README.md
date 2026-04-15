# Otis, KONE, Schindler, TK Elevator — signed controller firmware
# and connected elevator cloud telemetry

The **big-four vertical-transport** OEMs — **Otis, KONE, Schindler,
TK Elevator** (formerly ThyssenKrupp) — plus **Mitsubishi Electric,
Hitachi, Fujitec** operate and maintain a combined installed base
of **~22 million elevators, escalators, and moving walks** worldwide.
Every commercial high-rise, hospital, subway station, airport, and
residential tower on the planet runs one of their controllers.

All four big-four OEMs have pushed their installed fleets onto
cloud-connected predictive-maintenance platforms over 2018-2024:

- **Otis ONE / Otis CompassPlus / eView / Otis Service App** —
  Otis's connected-elevator backbone, ~1M units subscribed.
- **KONE 24/7 Connected Services** — LoRa/4G dispatch + diagnostics,
  ~600k units.
- **Schindler Ahead** — similar; large footprint in European
  commercial real estate.
- **TK Elevator MAX** — Microsoft-Azure-hosted predictive
  maintenance.

Each of these platforms — plus the underlying controller firmware
on the modernization / new-install side — relies on RSA for:

## 1. Controller firmware signing
OTIS Gen2 / SkyRise, KONE MonoSpace / UltraRope, Schindler 3300 /
5500 / 7000, TK Evolution / Synergy controllers. All ship with
RSA-2048 (older) or RSA-3072 (post-2019) firmware images signed
by the OEM release HSM. Controllers refuse un-signed firmware via
secure bootloader.

## 2. Service-tool authentication
Field-service technicians connect laptops + handheld service
tools (Otis SVT, KONE TMS, Schindler BT/BIONIC, TK ACCESS) that
authenticate to the elevator controller over Bluetooth, Wi-Fi, or
RS-485 using per-technician RSA client certificates issued by the
OEM's technician-PKI. Service-mode commands (rescue operation,
adjust door timing, change speed profile, enter inspection mode)
require authenticated service-tool sessions.

## 3. IoT gateway → cloud telemetry
Every cloud-connected elevator has a gateway (Otis-branded OTIS
ONE box, KONE DX 24/7 Gateway, Schindler Ahead CUBE, TK MAX 24/7).
These gateways run embedded Linux + OpenSSL and push telemetry
(door cycle count, motor vibration, temperature, position
profile, fault codes) to OEM cloud over MQTT-over-TLS mutual
auth. Gateway certs are RSA-2048+.

## 4. Safety-certified firmware updates (EN 81-20/50)
Elevator safety-function firmware is **certified** under EN 81-20
/ EN 81-50 (ASME A17.1 / B44 in North America). Safety-rated
functions: overspeed governor, rope-brake, ascending-car-
protection, unintended-car-movement protection (UCMP). These
subsystems are firmware-distinct and signed by a distinct OEM
CA whose keys are under the OEM's safety-certification regime
(TÜV SÜD, TÜV Rheinland, UL, CSA).

## 5. Building-management system integration
Elevators publish their state and accept destination-dispatch
requests via BACnet-over-IP or KNX. B2B building-automation
integrators (Johnson Controls, Honeywell, Siemens Desigo, Schneider
EcoStruxure) ingest this via authenticated sessions with RSA-
based cert exchange.

## Scale

- 22 million elevators globally, 1B daily rides worldwide
- New installs: ~1.1M units/year
- Connected-elevator subscriber base: ~3-4M units and growing
- Otis alone maintains ~2.1M units, KONE ~1.7M, Schindler ~1.3M,
  TK Elevator ~1.2M

## Breakage

A factoring attack against:

- **An elevator-OEM firmware-signing CA**: attacker ships signed
  firmware accepted by every fielded controller of that OEM.
  Scenarios:
    * Safety-function tampering: disable UCMP (unintended car
      movement protection) or ascending-car overspeed. In a
      worst case, unintended car movement with doors open — fatal.
    * Mass denial-of-service: brick all connected elevators of
      one brand simultaneously → high-rise evacuation
      impossible, critical-facility disruption (hospitals, jails,
      subways).
    * Service-fee shakedown: silent fault-injection forcing
      emergency service calls.
- **A technician-PKI CA**: attacker mints service-tool certs,
  enters service mode on arbitrary elevators, bypasses safety
  interlocks.
- **A cloud-gateway client-cert CA**: attacker forges telemetry
  (hide real faults; trigger phantom-maintenance dispatches;
  manipulate usage-based-billing data from KONE/Otis managed-
  service contracts).

Elevator lifecycle is **25-30 years**. Controller replacement is
a major modernization project (typically >$100k per shaft). A
factoring compromise cleanup is a multi-decade program running
on the normal modernization capital cycle.
