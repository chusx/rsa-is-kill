# Electronic Toll Collection — transponders, gantries, interop hubs

Electronic Toll Collection (ETC) operates at continental scale
across multiple non-interoperable but RSA-dependent ecosystems:

- **E-ZPass** (US NE corridor, 18 states + Canada ON, ~50M tags)
- **SunPass** (FL), **TxTag** (TX), **FasTrak** (CA), **I-PASS**
  (IL), **PeachPass** (GA), **TOLL2Go** (TN), **BancPass** — all
  interoperating via **IAG (Interagency Group) Hub Reconciliation**
  and the **E-ZPass Group Hub**.
- **Autostrade Telepass** (Italy, ~7M tags), **Bip&Go / Liber-t**
  (France), **VIA-T** (Spain), **TrollyPass** (Norway), **Fremtind**
  (Scandi), **EETS** (European Electronic Toll Service, cross-EU
  roaming).
- **ETC 2.0** (Japan's upgraded 5.8-GHz DSRC system, MLIT-mandated
  RSA-signed DSRC frames on every highway gantry nationwide),
  **Hi-Pass** (Korea), **HKeToll** (Hong Kong 2023+ free-flow).

## RSA touchpoints

### 1. Tag provisioning / personalization
Each transponder (TransCore eGo, Kapsch TRP-4010, Q-Free Gemini,
Siemens Mobility SFL) gets a unique identity written at
personalization. In the 2nd-gen protocols (ISO 14906-compatible
CEN-DSRC at 5.8 GHz, plus ISO 19299 EETS), tags carry an RSA-2048
keypair and a CSC (Concession / Service Centre) signed X.509
identity cert. Personalization is performed inside an HSM-backed
PKI at the toll agency.

### 2. Gantry-to-tag authentication
In the free-flow European CEN-DSRC model and in Japan ETC 2.0, the
roadside unit (RSU) challenges the on-board unit (OBU); the OBU
responds with a fresh signature bound to the transaction nonce
using its RSA private key.  RSU chain-verifies the tag's cert up
to the pinned concession root before debiting the toll.

### 3. Interop hub reconciliation
The IAG Hub (US) / EETS routing nodes (EU) reconcile transactions
between issuing agencies and the agency where the trip occurred.
Settlement files flow between hub nodes as XMLDSig-RSA-signed
reconciliation records.

### 4. Customer portals + license-plate billing
License-plate video-billing portals (Toll By Plate, FreeFlow,
Toll Express) authenticate consumer logins via OAuth/OIDC + TLS,
and issue receipt PDFs with RSA-signed digital signatures for
reimbursement claims (business travel, fleet services).

## Deployment footprint

- ~150 billion toll events per year globally processed through
  RSA-signed workflows.
- Fleet telematics (Geotab, Samsara, Fleetmatics) auto-log toll
  transactions via signed IFTA-report summaries.
- Logistics-industry fuel-tax reconciliation (IFTA) feeds off
  signed toll + fuel records.
- Insurance PAYD / PHYD (Pay-As-You-Drive / Pay-How-You-Drive)
  telematics pulls trip data that's cross-referenced against
  signed tolling records.

## Breakage

A factoring attack against:

- **A toll-agency CSC root** (e.g. MTA E-ZPass, TxDOT, Autostrade
  Telepass): attacker mints an OBU cert, rides the toll system
  free at scale, or — worse — forges tolling records against
  arbitrary vehicle IDs, fraudulent-billing random motorists.
- **An EETS routing-node signing key**: cross-border settlement
  files become forgeable; financial reconciliation between EU
  toll authorities (~€10B/year) enters evidentiary ambiguity.
- **A DSRC RSU firmware signing key** (Kapsch, TransCore,
  Mitsubishi Heavy Industries): attacker pushes malicious RSU
  firmware that silently tamper-logs valid tags as paid-when-not
  or unpaid-when-paid.  Covert revenue theft at the highway-
  gantry level.

Transponder fleets are 7-10 year deployed assets and reissuance
is a major operational program. A factoring break produces
multi-year revenue-integrity and civil-liberty (wrongful-billing)
consequences.
