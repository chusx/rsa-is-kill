# Fuel forecourt — dispenser PEDs, FCCs, and DHC-to-Exxon/Shell hubs

Every fuel dispenser in the US (~150,000 retail stations, 1+M
dispensers), EU, and ANZ markets pumps fuel through a tightly-
regulated retail-payments infrastructure:

- **Dispenser PED / EPP** (Encrypting PIN Pad, usually integrated
  into a **PCI PTS POI**-certified unit on the pump): Verifone
  MX925, Ingenico iSC250 in-dispenser modules, Wayne / Gilbarco-
  Veeder-Root FlexPay variants.
- **Forecourt controller (FCC)**: Wayne Fusion, Gilbarco Passport,
  Dover Tokheim DFS, NCR Radiant. Speaks to the dispensers' PEDs
  + fuel-control electronics (FCE) + loyalty/printer peripherals.
- **Store POS**: NCR, Verifone Commander, Gilbarco Passport (dual-
  role as FCC + POS), Toshiba 4690.
- **Back-office + DHC (Direct Host Connect)**: Conexxus DHC-IP
  standard for EMV-at-the-pump settlement, routed to acquirer +
  fuel-retailer brands (Exxon-Mobil, Shell, BP, Chevron, 7-Eleven,
  Circle K, Alimentation Couche-Tard, TotalEnergies).

## RSA-critical layers

### 1. Dispenser EPP firmware + RKI
Identical model to `pos-pci-pts/`: RSA-signed firmware, TR-34
Remote Key Injection of DUKPT BDK-derivations. Here the stakes
differ because a single forecourt runs 8-32 dispenser pumps,
each with an EPP; fleet-wide compromise at a station owner-
operator (e.g. Couche-Tard operates ~13,000 stations) is a
large-scale PIN-harvesting platform.

### 2. EMV-at-the-pump L2 kernel signing
EMVCo-approved L2 kernels for unattended petroleum (UAT Type
Approvals) carry RSA-signed binaries. Pump BIOS verifies the
kernel before granting access to the secure channel to EPP.

### 3. DHC-IP / Conexxus retail transaction hub
The DHC (Direct Host Connect over IP) standard is the cross-
brand fuel-retail settlement protocol. Site-to-hub connections
authenticate over TLS 1.2+ with RSA-2048 mutual-auth client
certs issued by the brand's back-office PKI (Chevron, Shell,
Phillips 66). Every gallon pumped → authorization request
signed-in-flight between site FCC and brand DHC.

### 4. Fleet card processing
Wright Express (WEX), Comdata, FleetCor, US Bank Voyager — all
authenticate fleet-card swipes at the pump via a cross-
acquirer network that layers on top of standard card-network
TLS-PKI plus a per-fleet issuer signing layer for telematic +
fuel-consumption analytics.

### 5. Tank monitoring / ATG
**Veeder-Root TLS-4xx** automatic tank gauges report inventory
up to compliance portals (EPA 40 CFR 280 leak-detection). Many
of these portals require signed records; a signed anomaly log
is the primary evidence in EPA investigations of underground
storage-tank compliance.

## Scale

- ~$1T/year US fuel retail sales
- ~150B gallons pumped/year in US
- Skimming attacks on forecourt pumps cost retail industry ~$1B
  annually (FBI estimate); the PCI PTS + signed-firmware
  architecture is the ONLY reason that number is not an order
  of magnitude larger.

## Breakage

A factoring attack against:

- **A dispenser-vendor firmware-signing key** (Wayne / Gilbarco /
  Dover): attacker distributes a signed firmware that silently
  exfiltrates magstripe + EMV + PIN data from every pump running
  that dispenser generation. EPAs of millions of pumps (Wayne +
  Gilbarco combined ≈ 65% of US dispensers) stripped of their
  cryptographic integrity guarantee.
- **A brand DHC CA** (ExxonMobil, Shell, Chevron): forged
  settlement records flowing into the brand's back-office; fuel
  "purchased" at a station where no pump actually dispensed,
  or vice versa — retail fraud at the brand-accounting layer.
- **A fleet-card issuer signing key** (WEX, Comdata): forged
  fleet-card authorization; each fleet card carries a ~$10k/month
  line of credit for fuel purchases.
- **An ATG / Veeder-Root tank-monitoring signing root**: EPA
  environmental-compliance evidence chain collapses. Under-
  reported leaks from underground storage tanks become
  deniable, complicating enforcement.

Dispenser firmware rotation at a retail chain is 3-5 years
between replacement cycles. A factoring compromise has a
multi-year cleanup window during which PIN + card data harvesting
continues at attacker discretion.
