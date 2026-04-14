# autosar-ecu-hsm — RSA in automotive ECU hardware security modules

**Standard:** AUTOSAR SecOC R23-11 / EVITA (E-safety Vehicle Intrusion proTected Applications)  
**Hardware:** Infineon AURIX TC3x HSM, NXP S32G HSE, Renesas RH850 ICUMHA  
**Industry:** Automotive OEM — every modern vehicle (100-150 ECUs per car)  
**Algorithm:** RSA-2048/3072 (firmware signing), ECDSA P-256 (TLS/AUTOSAR)  
**PQC migration plan:** None — AUTOSAR R23-11 has no PQC algorithm family; HSM silicon is fixed

## What it does

Modern vehicles have 100-150 Electronic Control Units (ECUs) — engine, brakes,
steering, infotainment, ADAS. Each ECU contains a Hardware Security Module (HSM)
— a dedicated crypto core integrated into the SoC silicon.

RSA is used for:
- **ECU firmware authentication**: OEM signs firmware images with RSA-2048.
  The ECU HSM verifies before flashing. Keys burned at ECU manufacture.
- **V2C OTA update channel**: TLS with RSA certificates for vehicle-to-cloud
  communication (firmware downloads, fleet management)
- **AUTOSAR Crypto Stack**: `CRYPTO_ALGOFAM_RSA` (0x04) is the RSA family
  identifier. No PQC algorithm family is defined in AUTOSAR R23-11.

## Why it's stuck

AUTOSAR defines the software stack but the HSM is physically fixed in silicon:

- **Infineon AURIX TC3x**: HSM firmware is ROM — it cannot be field-updated.
  The cryptographic primitives are hardwired at manufacturing.
- **NXP S32G HSE**: firmware-updateable HSM, but no PQC firmware released.
- **Renesas RH850**: SHE (Secure Hardware Extension) is hardware-only, no PQC.

The deeper problem: replacing the OEM firmware-signing RSA key requires:
1. Physical ECU access (manufacturing or dealer tool)
2. A new key ceremony
3. Revalidation under UN R155/R156 (CSMS) and ISO/SAE 21434
4. Potentially a new type approval in some jurisdictions

Vehicle lifespan: 15-20 years. ECUs provisioned in 2025 are expected to be
operational in 2045. No automotive OEM has published a PQC migration roadmap.

## impact

ECU firmware signing keys are what stand between "your car runs the manufacturer's software" and "your car runs whatever someone decided to flash to it." there are a lot of cars.

- forge a malicious firmware update that passes RSA-2048 verification, flash it via OTA or a workshop tool, get persistent vehicle compromise that survives ignition cycles and "factory reset"
- ADAS ECU controls autonomous emergency braking and lane keeping. forged firmware can disable safety functions or inject false object detection events
- brake controller ECU: manipulate brake force distribution. the consequences there are fairly obvious
- one compromised OEM signing key affects every vehicle in that model line that accepts OTA updates. we are talking potentially millions of vehicles from a single key compromise
## Code

`autosar_secoc_rsa.c` — AUTOSAR CsmSignatureVerify interface, `EVITA_RSA_PublicKey`
struct, UDS firmware update flow, and HSM silicon inventory (AURIX/S32G/RH850)
with PQC support status.
