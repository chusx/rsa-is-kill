# FANUC / KUKA / ABB / Yaskawa industrial robots — signed option
# board firmware, safety-software attestation, MTConnect PKI

Industrial robots from the big-four (FANUC, KUKA, ABB, Yaskawa
Motoman) plus Kawasaki, Staubli, Denso, Mitsubishi, Universal
Robots, Epson, Omron-Adept collectively number **~4 million
installed units worldwide**. Every auto assembly plant, electronics
manufacturing line (Foxconn, Pegatron, Luxshare), aerospace cell
(Boeing, Airbus, Spirit AeroSystems, GKN), food-packaging line,
semiconductor fab (ASML wafer-handling, TEL, Applied Materials)
runs robots whose controllers rely on RSA at multiple levels.

## RSA-dependent subsystems

### 1. Controller firmware + option-board signing
FANUC R-30iB Plus / R-30iB Mini Plus, KUKA KR C4 / C5, ABB IRC5 /
OmniCore, Yaskawa DX100 / YRC1000 — all controllers verify signed
firmware at power-on. Safety-certified variants (FANUC iRVision
Safe, ABB SafeMove, KUKA.SafeOperation) have additional RSA-signed
safety-option firmware that TÜV + UL have certified for Cat 3 /
PLd / SIL 2 functional-safety use (ISO 13849-1, IEC 61508, IEC
62061).

### 2. Teach Pendant + HMI application packages
Every downloaded teach-pendant app (KUKA smartPAD, FANUC iPendant
Touch, ABB FlexPendant, Yaskawa SmartPendant) is RSA-signed by
the OEM. Field modifications by end-users or system integrators
require OEM-signed packages.

### 3. Program upload / OPC UA digital nameplate
I4.0 initiatives (Industrie 4.0, IIC) mandate **OPC UA** (see
`opcua-open62541/`) as the standard robot-to-MES protocol. Every
robot cell registers in the plant's OPC UA GDS (Global Discovery
Server) with a per-robot RSA-2048 cert. MTConnect (ANSI/MTC1
standard) XML data streams for robot telemetry ride the same TLS
mutual-auth.

### 4. Safety PLC pairing
Robots integrate with safety PLCs (Siemens SIMATIC F-CPU, see
`siemens-s7-tia/`; Rockwell GuardLogix; B&R X20) via PROFIsafe /
CIP Safety / openSAFETY. The initial binding of a safety PLC
to a robot controller uses an RSA-signed pairing certificate —
only paired devices can exchange safety signals.

### 5. Vision system + force sensor integration
FANUC iRVision, Cognex In-Sight, Keyence CV-X, ATI-IA FT Sensors
all ship signed firmware + TLS-authenticated configuration
updates. Machine-vision calibration files carry signatures to
prove they originate from OEM-validated cameras.

### 6. Remote service + predictive maintenance
FANUC ZDT (Zero Downtime), KUKA iiQoT, ABB Ability Connected
Services, Yaskawa Cockpit — every cloud-connected robot sends
telemetry over TLS. Cert pinning to OEM cloud root; over-the-air
firmware pushes are RSA-signed.

## Scale and safety-criticality

- Global robot installed base: ~4.3 million units
- Robot-involved fatalities: ~1/year recorded in US (OSHA), but
  each incident requires extensive root-cause + cryptographic-
  integrity investigation if safety firmware is involved
- Manufacturing-sector value-add touched by these robots: ~$7T
  global
- UN R155 (automotive) cybersecurity regulation has 2024
  implications for in-plant robots assembling UNECE-regulated
  vehicles: the robot fleet needs cryptographic-integrity audit
  as part of the type-approval paper trail

## Breakage

A factoring attack against:

- **An OEM firmware-signing CA** (FANUC, KUKA, ABB, Yaskawa):
  attacker distributes malicious controller firmware that the
  robot's bootloader accepts. Scenarios:
    * Subtle motion-path perturbation → scrap/defect rate on
      assembly line quietly rises.
    * Disabling of collaborative-mode speed-and-separation
      monitoring → human worker injury; safety-case collapse.
    * Coordinated across plants → manufacturing-disruption
      operation at geopolitical scale.
- **A safety-option signing key**: safety-rated functions (zone
  monitoring, velocity limiting) become untrusted; TÜV/UL safety
  certification on every affected unit is invalidated pending
  re-certification — a 6-12 month process per cell.
- **An OPC UA GDS / plant-CA RSA key**: attacker mints a robot
  cert, joins the plant OPC UA namespace, injects forged MES
  commands to robot cells (e.g. "start program 42" commanding a
  weld on empty fixture, or in a worst case a movement command
  while a human worker is in the work envelope after safety
  override).

Industrial-robot fleet lifecycle is 10-20 years. Firmware-signing
key rotation requires coordination with every end-user plant. A
factoring compromise has multi-year remediation timescales during
which safety-case integrity is in question.
