# AMI smart metering — DLMS/COSEM + ANSI C12.22 signed firmware

Smart electricity meters deployed across every major utility
worldwide run either:

- **DLMS/COSEM** (IEC 62056, used in 95% of Europe, Asia, LATAM,
  Africa, Australia) — "Device Language Message Specification /
  Companion Specification for Energy Metering".
- **ANSI C12.22** (used in North America, C12.19 data model over
  C12.22 transport) — backhaul from meters to AMI head-ends.

Both stacks depend on RSA at three layers:

1. **Firmware image signing** — every OTA firmware update pushed
   by the utility to field meters is RSA-2048 or RSA-3072 signed
   by the manufacturer's release HSM. The meter bootloader
   verifies the signature before flashing. Meter vendors: Landis+Gyr,
   Itron, Kamstrup, Sagemcom, Honeywell Elster, Aclara, Iskraemeco,
   EDMI. ~1.5 billion smart meters globally.

2. **DLMS HLS Mechanism 7 (digital signature)** — one of the high-
   level security modes defined in the DLMS/COSEM "green book"
   uses RSA-based client authentication during Application
   Association establishment. Head-end system (HES) and meter
   mutual-authenticate with RSA.

3. **ECDSA-backed COSEM objects with RSA-backed PKI** — even when
   meter↔HES uses ECDSA signatures per IEC 62056-5-3 Security
   Suite 1, the underlying certificate chain anchors at a utility
   root CA typically run with RSA-2048/4096 for legacy
   interoperability with ICT-team PKI infrastructure.

## Deployment footprint

- EU SO 2020 directive mandated smart-meter rollout: 80%+ of EU-27
  households now on DLMS meters.
- UK SMETS2 — every British home that's had a smart-meter upgrade
  since 2019 runs DCC (Data Communications Company) WAN with DLMS
  and a PKI rooted at the DCC's RSA-2048 CA.
- Italy's Enel Open Meter (30+ million units), Spain's Iberdrola
  rollout (12 million), France's Linky (Enedis, 37 million),
  Germany's BSI-certified SMGW with a PKI rooted at the BSI Root
  CA (RSA-3072+).
- US investor-owned utilities via Itron OpenWay, Landis+Gyr Gridstream
  — FirstEnergy, ConEd, PG&E, SCE, Duke Energy, Southern Company.
- India's Revamped Distribution Sector Scheme (RDSS) — 250 million
  smart prepaid meters planned by 2026, all DLMS/COSEM.

## Breakage

A factoring attack against:

- **A meter-vendor firmware signing key** (Landis+Gyr, Itron,
  Kamstrup): attacker signs firmware that the entire field fleet
  of that vendor accepts. At regional-DSO scale (millions of
  units) this is a mass grid-destabilization primitive:
    * Zero out billing registers.
    * Coordinate simultaneous load disconnect (every meter has a
      remote-disconnect relay) — synchronized drop of tens of MW.
    * Brick devices en masse; restoration requires physical truck
      rolls to each meter.
- **A national Smart-Meter Gateway Root CA** (e.g. BSI's German
  SMGW PKI): attacker mints rogue SMGWs, intercepts every meter
  reading for every household on that NWF, forges consumption
  data for billing manipulation.
- **A DCC-level CA (UK)**: cross-DNO compromise across every British
  SMETS2 household (~30 million) — readings, disconnect/reconnect
  commands, prepayment-top-up authorizations all forgeable.

Smart meters are 15-year-deployed assets. Firmware rotation is
slow (quarterly at best, annual or less at typical utility);
field recovery from a key compromise requires either massive
truck-roll campaigns or, in the worst case, physical meter
replacement — a multi-year, multi-billion-euro program per DSO.
