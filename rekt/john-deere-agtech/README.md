# John Deere / CNH / AGCO / Kubota — signed ag-equipment firmware,
# Operations Center telematics, prescription-map chain-of-trust

Global row-crop agriculture runs on a duopoly-plus: **John Deere**
(~53% North American large-tractor share), **CNH Industrial** (Case
IH, New Holland, Steyr, Magirus), **AGCO** (Fendt, Massey Ferguson,
Challenger, Valtra), **Kubota** (dominant in orchard/specialty +
global compact), **CLAAS** (harvesters in Europe). Combined installed
base: **~15 million powered agricultural machines** worldwide with
ISOBUS-class electronics; ~3M of these are cloud-connected.

## RSA usage

### 1. ECU / controller firmware signing
John Deere Gen4 displays, StarFire receivers, AutoTrac steering,
JDLink modems; CNH AFS Pro 1200 / PLM Intelligence; AGCO Fuse / JCA
TaskDoc; Kubota K-Link — all consume RSA-signed firmware pushed
over-the-air. Deere specifically has a chain-of-trust from tractor
Central Vehicle ECU (CVE) down to 50+ ISO 11783 controllers on the
implement bus.

### 2. Operations Center / Land.db / Fuse cloud telemetry
Deere Operations Center, CNH AFS Connect / PLM Connect / FieldOps,
AGCO Fuse, Kubota KubotaNow — each platform receives per-machine
telemetry over TLS with a per-machine client cert (RSA-2048 issued
at dealer commissioning). Daily upload: yield maps, as-applied maps,
machine-health, geofence breaches.

### 3. Prescription-map + boundary signing
Variable-rate application ("Rx") maps — nitrogen, seed population,
fungicide, irrigation — are authored by agronomists in third-party
software (Climate FieldView, Granular, MyJohnDeere, FarmLogs), signed
by the data platform, and downloaded into the implement controller.
Signed boundary files prevent off-field application (endangered
species, organic-zone setbacks, riparian buffers).

### 4. Guidance / RTK correction delivery
StarFire RTK, John Deere SF-RTK, Trimble CenterPoint RTX, Topcon
TopNET — all deliver NTRIP-wrapped correction streams over TLS
mutual auth. Per-subscriber RSA client certs bind the correction
feed to a paid licence; centimetre-accurate autonomy (~10M
subscribed machines) depends on this feed.

### 5. Right-to-repair / emissions-compliance signing
Post-2024 US right-to-repair MOU commits Deere and others to
releasing diagnostic-mode tools, but *diagnostic signing keys*
remain OEM-held; aftermarket repair software presents a signed
authorisation token to the CVE before service-mode unlocks.
EPA Tier 4 Final / EU Stage V emissions-strategy signing is
regulatorily mandated — if the ECU would let unsigned cal files
run the engine, the certificate of conformity is void.

## Scale

- ~15M connected/connectable ag machines worldwide
- Deere Operations Center: ~500k active operators, ~250M ha managed
- Global food production touching these fleets: >$4T farmgate
- Planting window pressure: in spring, a US Midwest grower may
  have a 10-day window to plant 5,000 ha — a fleet-wide lockout
  mid-window causes economy-scale yield loss

## Breakage

A factoring attack against:

- **A Deere / CNH / AGCO firmware-signing root**: signed firmware
  pushed fleet-wide that bricks, ransomware-locks, or silently
  degrades. Modern tractors are already remotely-lockable — when
  Ukrainian farmers' Deere tractors looted by Russian forces in
  2022 were remotely disabled, it demonstrated the capability. A
  malicious firmware push at scale during planting / harvest is
  a strategic-food-supply attack.
- **A prescription-map signing root**: attacker distributes
  signed Rx maps calling for 10× nitrogen or mis-located
  herbicide zones. Crop destruction + groundwater contamination
  across hundreds of thousands of hectares.
- **An RTK correction-stream CA**: attacker forges corrections
  that drift the guidance frame by half a row-width across a
  subscriber base; a growing season of crooked rows, yield loss,
  and machinery damage at headland turns.
- **An Operations Center client-CA**: forge as-applied records
  for USDA FSA / EU CAP subsidy claims, RFS-2 feedstock proofs,
  crop-insurance loss adjustments — billions in regulatory
  fraud exposure per year.

Tractor lifecycle is 15–25 years. Rotation of a compromised
firmware root requires dealer visits to every machine on the planet
with that OEM's Gen4+ electronics — a decade-long programme.
