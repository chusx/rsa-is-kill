# Semiconductor lithography — reticle identity + fab
# manufacturing-execution chain-of-custody

Every leading-edge logic + memory fab runs under a cryptographic
regime binding **reticle (photomask) identity** → **scanner job**
→ **wafer lot** → **MES traceability** → **yield + binning**.
ASML EUV (TWINSCAN NXE:3800E / High-NA EXE:5200) jobs are signed;
reticle-inspection / review files are signed; customer-IP
protection (fabless designers' mask data) rests on those signatures.

## Players

- **Scanner OEMs**: ASML (EUV + DUV), Canon (Nikon competitor),
  Nikon NSR
- **Mask writers + inspection**: Applied Materials / Hitachi
  High-Tech / KLA (5xxx, 7xxx), Lasertec (EUV actinic inspection
  MATRICS / ACTIS)
- **Fabless customers**: Apple, Nvidia, AMD, Qualcomm, Broadcom,
  MediaTek, Marvell — whose IP lives on reticles
- **IDMs / foundries**: TSMC, Samsung Foundry, Intel, Micron, SK
  hynix, GlobalFoundries, UMC, SMIC
- **Mask shops**: Photronics, Toppan Photomask, DNP / HOYA,
  captive mask shops inside TSMC / Samsung / Intel
- **MES/CIM vendors**: Applied Materials SmartFactory, Siemens
  Opcenter Execution Semiconductor, Critical Manufacturing

## RSA usage

### 1. Reticle identity + mask-data encryption
Fabless customer signs mask-data (OASIS / GDSII stream) before
shipping to the mask shop. Mask shop signs the mask-inspection
result. The physical reticle carries a scanned identifier whose
binding to the signed mask-data manifest is the IP-protection
anchor.

### 2. Scanner job-file signing (ASML NXE / EXE recipes)
Production recipes for ASML EUV scanners (illumination mode,
dose, focus offset, overlay correction) are fab-IP. Recipes are
signed by the process-integration team; scanner verifies before
executing the exposure.

### 3. Reticle-library-management signed release
Reticles cycle between inspection, cleaning (HAMATECH / Suss
MicroTec), storage, and stepper. Each hand-off is a signed MES
event — PKE-bound pod (ASML EUV Pod) + scanned reticle ID.

### 4. Yield-data + parametric-test signing
Wafer-test (KLA probe cards, Advantest / Teradyne ATE) generates
signed bin maps. Yield-forensics + customer chargeback rests on
signed artefacts.

### 5. Tool-to-tool recipe propagation
Multi-tool tracks (e.g. litho cells: scanner + track + inspection)
exchange recipes. MES-signed recipe deployments prevent a rogue
technician from injecting drift at any single tool.

### 6. ASML remote-diagnostics signed upload
ASML telemetry channel (crated into their "EUV fleet" support
model) uses signed diagnostic dumps. Foundries gate what leaves
the fab; signatures ensure authenticity on ASML's side + prevent
tampering en route.

## Scale + stickiness

- EUV scanners installed: ~250 globally (each ~$200M); High-NA ~15
- Reticles per modern node: 60-80 layers × ~$500k-$1M each
- Mask-data bytes per node: multi-TB per customer tapeout
- Recipe footprint per scanner: thousands of job definitions
- Recertification cost (ASML Qualified Production Process): any
  crypto change is a multi-fab multi-customer QPP re-run

Why RSA stays: fab tools have 15-20 year depreciation horizons.
OASIS / GDSII toolchains embed RSA via vendor SDKs (Cadence,
Synopsys, Siemens EDA). ASML scanner firmware is signed under
ASML's vendor PKI; customer requalification on a new algorithm
is measured in wafer-lots of lost yield.

## Breakage

- **Fabless customer mask-signing key factored**: reticle-IP
  theft with plausible-deniability (attacker mints valid
  "customer-approved" mask manifests for modified designs);
  counterfeit chips from stolen mask-data could carry forged
  provenance.
- **Scanner recipe-signing key factored**: attacker-crafted
  recipe degrades dose / focus / overlay across a fab for days
  before detection — silent yield sabotage worth $B+.
- **ASML vendor FW root factored**: malicious scanner firmware
  across the entire EUV installed base; geopolitical-scale
  semiconductor-industry disruption.
- **Reticle-library-management MES root factored**: wrong
  reticle → wrong wafer lot exposure; irrecoverable wafer scrap
  + IP leakage across customer boundaries (fabless-customer A's
  reticle used while fabless-customer B's lot is logged).
