# FAA Remote ID & LAANC — authenticated drone broadcasts

**FAA Part 89 Remote ID** (14 CFR §89) has been mandatory for all
drone flights in the US since **September 16, 2023**. Remote ID
requires every flying drone to broadcast identity, position,
altitude, speed, and control-station location. ASTM F3411-22a
defines the broadcast protocol (Bluetooth LE + Wi-Fi NaN frames).

A parallel global mandate: **EU Delegated Regulation 2019/945 +
2019/947**, phased in through 2024, requires similar Remote ID
conformance for any drone operating under the "Open" or "Specific"
category across EU-27.

## Where RSA enters

### 1. Signed Remote ID broadcasts (ASTM F3411-22a authenticated)
The most recent F3411 revision introduces an authenticated-message
option: Remote ID frames can be signed with the operator's RSA-
2048 private key, certificate chain to an FAA-recognized trust
anchor.  Not mandatory in the US today, but several enterprise
drone platforms (Skydio X10D, Matrice 350 RTK, Autel EVO Max 4T)
implement it and counter-UAS / UTM providers (AirMap, Altitude
Angel, Kittyhawk) validate it.

### 2. LAANC authorization
**LAANC** (Low Altitude Authorization and Notification Capability)
is the FAA's real-time airspace-authorization system for
controlled airspace below 400 ft. An approved service supplier
(USS): AirMap, Skyward (Verizon), Aloft, UASidekick. Every
authorization request flows over TLS-mutual-auth with RSA-2048+
USS client certs; every grant is an RSA-signed authorization
token the drone can present on-demand during enforcement action.

### 3. Drone firmware signing
DJI, Skydio, Autel, Parrot, BRINC, Teal Drones (Red Cat) sign
firmware images with RSA-2048+ release keys. Boot loader
verifies signature before executing new firmware.

### 4. Manufacturer declaration of compliance
FAA-required Declaration of Compliance (DoC) filings are signed
documents submitted through the FAA's e-filing portal. Operator
registration (FAA TRUST + B4UFLY) relies on RSA-signed credentials.

### 5. UTM / U-space
Europe's U-space regulation (EU 2021/664 + 2021/665) mandates
authenticated flight-plan submission and traffic-information
exchange; the reference DSS (Discovery & Synchronization Service)
architecture (implemented by InterUSS Platform) uses JWT-RS256
service-to-service auth.

## Fleet scale

- ~1.1 million drones registered with FAA (Part 107 + recreational)
- ~300,000 commercial Part 107 pilots
- LAANC processes >1 million authorizations per year
- EU: ~5 million registered drones post-2024 mandate
- Global consumer + commercial drone fleet: >50 million units

## Breakage

A factoring attack against:

- **The FAA-recognized Remote ID trust anchor** (a vendor-CA chain
  the FAA is publishing as part of enforcement tooling): attacker
  signs broadcasts impersonating arbitrary operator IDs; counter-
  UAS investigations against illegal flights get attributed to
  random innocent operators, or genuine bad actors launder their
  identity through forged IDs.
- **A drone OEM firmware-signing key** (DJI, Skydio): attacker
  pushes signed firmware that silently disables geo-fencing, opts
  out of Remote ID, or redirects control telemetry. DJI alone
  sells ~70% of consumer drones; a fleet-wide firmware compromise
  is an airspace-safety scale incident.
- **A USS LAANC server cert**: MITM of authorization requests;
  grant forged authorizations for airspace where grants should be
  denied, or deny legitimate requests causing economic loss to
  commercial operators.
- **The InterUSS DSS RS256 signing key** for U-space: cross-
  operator flight-plan forging, denial of service against legit
  flights via forged conflict notifications.

Hardware-based geo-fencing enforcement in drones is 5-year-plus
deployed. Firmware-signing key compromise has no short-term
remediation; FAA enforcement response would be to ground affected
OEM models, which is politically and economically difficult at
consumer-fleet scale.
