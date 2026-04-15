# Blood / plasma / organ / tissue traceability — ISBT 128 +
# ICCBBA + UDI + Eurocode signed shipment records

Hospital blood banks, transfusion services, organ-procurement
organisations, and tissue-bank networks are interlinked by a
global traceability standard: **ISBT 128** (ICCBBA-maintained),
supplemented by **UDI** (FDA) and **Eurocode** (EU). Every donor
product carries a unique donation identification number (DIN)
whose issuance, shipment, recall, and transfusion are logged in
signed records across the supply chain.

## Players

- **Blood-service networks**: American Red Cross, Vitalant, NY
  Blood Center, NHS Blood & Transplant (UK), Établissement
  Français du Sang (EFS), DRK Blutspendedienst (Germany), Swiss
  Transfusion, Japanese Red Cross, Canadian Blood Services
- **Hospital blood-bank software**: Haemonetics SafeTrace Tx,
  Cerner CoPathPlus + Millennium Transfusion, Epic Beaker BB
  module, Mediware / WellSky HCLL Transfusion, SCC Soft SoftBank
- **Organ procurement**: UNOS / OPTN (US), Eurotransplant,
  NHSBT-ODT
- **Tissue / cord blood**: AATB-accredited banks (~150 US), CORD:USE,
  AlloSource, LifeNet Health, Musculoskeletal Transplant Foundation
- **Vendor supply chain**: Fresenius Kabi, Terumo BCT, Haemonetics,
  MacoPharma — apheresis + blood-component collection kits

## RSA usage

### 1. ISBT 128 product-label signatures
The ICCBBA-managed facility identifier assignments + DIN
generation logs are signed. Labels themselves carry data matrix;
shipping manifests that accompany them carry RSA-signed envelope
records for chain-of-custody.

### 2. Blood-bank middleware inter-facility signing
When a hospital requests a unit from a donor centre, the order
flows over an authenticated channel. Crossmatch / type-and-screen
results returned to the requesting facility are signed by the
originating laboratory.

### 3. HL7 / FHIR transfusion-administration signing
Transfusion-administration records (who hung which unit on which
patient at what time) are signed into the hospital EHR —
subject to 21 CFR Part 606.160 (blood-bank records) and 21 CFR
Part 11 (electronic records).

### 4. Organ allocation and offer-acceptance
UNOS DonorNet, Eurotransplant ENIS, NHSBT EOS — transplant offer
messages + acceptance / refusal responses carry signatures by
the responsible transplant-surgeon's credential. Signed audit
trail is evidentiary for allocation disputes + policy review.

### 5. Recall / look-back signing
When a post-donation donor illness necessitates product recall,
the recall message must reach all downstream custody hops and
patients. Recall messages are signed by the issuing blood service;
receivers track completion back.

### 6. FDA UDI-DI registry + BLA lot integrity
Biologics (Factor VIII, immunoglobulins, albumin) are manufactured
from plasma with UDI-tracked lot chains. FDA BLA / CBER lot-
release signing is RSA-backed.

## Scale + stickiness

- 118M blood donations/year globally
- ~14M US transfusions/year
- UNOS: ~40,000 US transplants/year
- AATB tissue recoveries: ~1M/year in US
- Plasma-derivative global market: ~$30B/year
- Every transfusion / transplant / tissue-graft event is a
  clinical-level transaction with signed audit trail

Why RSA is sticky: FDA-registered blood establishment software is
subject to 21 CFR 606 + AABB standards. Recertification after
crypto architecture change is non-trivial; vendors hold off major
refactors. ICCBBA's global coordination role means any rotation
must propagate through 6,000+ registered facilities globally.

## Breakage

- **ICCBBA facility-identifier / DIN signing root factored**:
  attacker mints valid DINs for counterfeit units — untested
  plasma / whole-blood entering the clinical supply chain,
  potentially with undisclosed infectious disease (HIV, HCV,
  HBV, Chagas). Direct patient-harm pathway.
- **Blood-bank middleware signing roots (Haemonetics/Cerner/
  Epic/WellSky)**: forged crossmatch results — wrong-ABO
  transfusion reactions (historically a fatality source).
- **Organ-allocation signing root (UNOS DonorNet etc)**:
  forged offer / acceptance / refusal chains — allocations go
  to non-entitled recipients, or life-saving offers mis-routed.
- **Recall signing root**: a genuine recall cannot be trusted
  (drop-rate of legitimate recalls); OR attackers forge false
  recalls to deny supply during an emergency.
- **BLA lot-release root (FDA CBER)**: plasma-derivative lots
  released-on-paper that weren't actually tested. Biologics
  market integrity collapses.

Blood/transplant lifecycles: individual units 5-42 days; donor
history + transfused-patient records retained for decades. A
cryptographic root compromise has a retrospective-trust surface
spanning decades of clinical records.
