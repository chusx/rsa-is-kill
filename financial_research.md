# Financial research — $ -impact re-estimation for Tier S / Tier A (and suspect-OOM) entries

Scope: ~40 systems where the dollar figure is load-bearing for tier placement, or where review suggested the current order-of-magnitude label is wrong. Each entry pins a headline number, names drivers, cites precedents, and flags whether it agrees / under- / over-shoots the current `summary.md` label.

**Convention.** "Revised $ impact" is the one-shot economic-damage envelope if a classical factoring break lands tomorrow and defenders use best-available remediation paths. Ranges are given as 90%-confidence intervals in OOM when we can; otherwise a point-estimate with a `low / medium / high` confidence tag.

**Anchor precedents (used throughout):**
- NotPetya: ~$10B global economic (Maersk $300M, Merck $670M–$1.7B, FedEx/TNT $400M–$1B, Mondelez $180M). [cshub.com](https://www.cshub.com/attacks/news/notpetya-costs-merck-fedex-maersk-800m), [cybereason](https://www.cybereason.com/blog/blog-notpetyas-fiscal-impact-revised-892-5-million-and-growing)
- SolarWinds: up to $100B cleanup across US gov+private. [rollcall](https://rollcall.com/2021/01/11/cleaning-up-solarwinds-hack-may-cost-as-much-as-100-billion/)
- CrowdStrike 2024 outage: Fortune-500 direct $5.4B (~$1B insured). [Fortune](https://fortune.com/2024/08/03/crowdstrike-outage-fortune-500-companies-5-4-billion-damages-uninsured-losses/)
- Equifax: ~$700M direct settlements, >$1.4B total incl. remediation. [NY AG](https://ag.ny.gov/press-release/2019/attorney-general-james-holds-equifax-accountable-securing-600-million-payment)
- Deepwater Horizon: $61.6B total BP liabilities. [BP](https://www.bp.com/en/global/corporate/news-and-insights/press-releases/bp-estimates-all-remaining-material-deepwater-horizon-liabilitie.html)
- Colonial Pipeline: $420M economic impact per day of outage. [Barracuda](https://blog.barracuda.com/2021/05/12/colonial-pipeline-cyberattack-reveals-economic-impact-of-ransomware)
- 737 MAX grounding: direct $20B, indirect $60B, ~$1B/month airline-side. [Wikipedia](https://en.wikipedia.org/wiki/Financial_impact_of_the_Boeing_737_MAX_groundings)
- BEC fraud: $2.77B reported US only in 2024, $55B cumulative since 2013. [FBI IC3](https://www.ic3.gov/PSA/2024/PSA240911)
- Siemens industrial-downtime study: Global-500 loses $1.4T/yr to unplanned downtime (~11% revenue). [Siemens 2024]
- US federal PQC migration: $7.1B 2025-2035 for civilian agencies. [White House](https://bidenwhitehouse.archives.gov/wp-content/uploads/2024/07/REF_PQC-Report_FINAL_Send.pdf)
- Broad enterprise PQC migration: ~$15B industry estimate. [PRNewswire](https://www.prnewswire.com/news-releases/the-15-billion-post-quantum-migration-nist-standards-are-final-nsa-deadlines-are-set-and-enterprise-cybersecurity-is-about-to-be-rebuilt-from-the-ground-up-302730679.html)
- SWIFT: $150T/year transacted. [Swift](https://www.swift.com/about-us/discover-swift/fin-traffic-figures)
- SAP: 77% of world transaction revenue touches SAP; $16T consumer purchases. [SAP](https://www.sap.com/documents/2017/04/4666ecdd-b67c-0010-82c7-eda71af511fa.html)
- Global cloud IT spend: $855B in 2024. [Holori](https://holori.com/cloud-market-share-2024-aws-azure-gcp/)

---

## Tier S cluster (Criticality=Exploitability=BlastRadius=5, Recoverability=1)

### arm-trustzone-tfa
**Revised $ impact**: $500B – $2T (medium confidence), silicon-refresh-bounded.
**Drivers**:
- Installed base: >30B ARM-A cores shipped lifetime; ~250M servers, ~3B active Android devices, Apple Silicon/M-series. [ARM investor](https://www.arm.com)
- ROM-fused RSA root: cannot be rotated without silicon respin. Average high-volume SoC NRE+mask set ~$50-500M; multiply by vendors (Qualcomm, MediaTek, Samsung, Apple, AWS Graviton, NVIDIA Grace, Ampere).
- Precedent: 737 MAX grounding ($80B combined) is the template for "regulator-forced fleet immobilization while rev-B silicon is produced"; scale to AWS/Azure datacenter fleets.
- Replacement cost: typical hyperscaler fleet refresh $10-30B per provider; auto/IoT embedded fleets uneconomic to replace.
**Comparison to summary.md** ("Hundreds of billions"): **agrees** on the bottom; upside could be $1T+ if auto+medical+aerospace TF-A-based silicon is in scope.

### android-avb
**Revised $ impact**: $100B – $400B (medium confidence).
**Drivers**:
- Installed base: >3B active Android devices. [SQ Magazine](https://sqmagazine.co.uk/android-statistics/) Samsung alone has >1B active.
- ROM-fused vbmeta keys per SoC vendor; AVB root cannot be rotated in-field on pre-Pixel-9 silicon.
- Replacement cost: device-replacement subsidy @ $50-150 per device × ~1-2B unrotatable devices = $100-300B.
- Precedent: Samsung Galaxy Note 7 recall ($5.3B) is the closest single-model analogue; Play-Integrity-gated banking app outage economics dominate.
**Comparison** ("Tens of billions"): **underestimated** — device-replacement arithmetic alone exceeds $100B.

### hsm-firmware-signing
**Revised $ impact**: $50B – $200B (medium confidence), financial-system-of-record adjacent.
**Drivers**:
- Global HSM market: $1.4–1.65B/yr new sales in 2024; Thales alone has 327k HSMs deployed performing 53T encryption ops/yr. [GM Insights](https://www.gminsights.com/industry-analysis/hardware-security-modules-market), [Thales]
- Installed base: ~500k–800k units across Thales/Entrust/Utimaco/IBM/AWS CloudHSM.
- Replacement cost: ~$30–50k per FIPS-140-3 Level-3 unit, plus re-key ceremonies → $15–40B physical refresh; but the real cost is the underlying financial systems that stop clearing while re-keying (see SWIFT/EMV entries).
- Precedent: No pure precedent; closest is Thales Luna firmware 7.3 migration (multi-year per-customer) scaled to mandatory industry-wide.
**Comparison** ("Trillions"): **overestimated** as a direct HSM cost. The trillions live downstream (SWIFT/EMV/ICSF); HSM layer itself is "tens to low hundreds of billions".

### adcs-windows
**Revised $ impact**: $100B – $500B (medium confidence).
**Drivers**:
- Installed base: ADCS in ~95% of Fortune 500, ~90% of Global 2000. [Infosecurity](https://www.infosecurity-magazine.com/news/active-directory-flaw-could/)
- Precedent per enterprise: NotPetya hit Maersk/Merck for $300M–$1.7B each via AD compromise; generalize to every AD-joined enterprise simultaneously.
- Replacement cost: enterprise PKI rebuilds typically $1–10M per large org × ~10k large-enterprise deployments = $10–100B direct; plus operational outage.
- Precedent: SolarWinds ($100B cleanup) is the closest mechanism match.
**Comparison** ("Hundreds of billions"): **agrees**.

### autosar-ecu-hsm
**Revised $ impact**: $200B – $1T (medium confidence).
**Drivers**:
- Production: ~90M new cars/yr; ~1.4B cars on road; average modern car has 50–100 ECUs each with HSM-gated firmware.
- Recall cost: $500–$2000 per vehicle non-OTA recall [eSync](https://esyncalliance.org/automakers-lose-900-million/); fleet-wide OTA triage still $300–500/car.
- 737 MAX precedent: one airframe, one regulator, $80B. Auto equivalent: every OEM, every regulator, >10^8 units.
- Replacement cost: ROM-fused ECU HSM keys in ~1B vehicles on road → $500/vehicle × 500M affected = $250B floor.
**Comparison** ("Hundreds of billions"): **agrees** bottom; likely trillion-class if NHTSA/EU-TypeApproval triggers restriction-on-use.

### iec62443-dtls-ot / siemens-s7-tia / iec62351-substation (OT cluster)
**Revised $ impact**: $300B – $1.5T combined (medium confidence).
**Drivers**:
- Precedent: Siemens 2024 study — Global-500 loses ~$1.4T/yr to unplanned industrial downtime. [Siemens] A coordinated OT-cert forgery event compresses a year's worth into days.
- Ukraine grid attacks (2015/2016) hit ~230k consumers for hours; generalized substation-wide event at G7 scale is multi-day.
- Installed base: ~3M S7 PLCs in industry; >100k IEC-61850 substations globally.
- Replacement cost: PLC firmware-refresh costs $5–20k per unit when certificates are ROM-resident.
**Comparison** (individually "Tens of billions"): **underestimated** cluster-wise. Any one substation attack is tens of billions; cluster-simultaneous is closer to Deepwater Horizon ($61B) per affected grid × multiple grids.

### ami-dlms-cosem
**Revised $ impact**: $50B – $200B (medium confidence).
**Drivers**:
- Installed base: 1.2B+ smart meters globally, 1.15B electricity alone, 63% use DLMS/COSEM. [DLMS UA](https://www.dlms.com/data-exchange-standards-analysis/)
- Replacement: $80–150 per meter × 500M DLMS-compliant = $40–75B physical.
- Precedent: European smart-meter rollout total budget ~€40–50B; re-do if crypto compromised.
- Ukraine-grid + Colonial-Pipeline-style outage per day @ AMI-dependent utility: $400M/day.
**Comparison** ("Tens of billions"): **slightly underestimated**; $50-200B more plausible once replacement is included.

### refinery-sis-iec61511
**Revised $ impact**: $50B – $300B (low confidence).
**Drivers**:
- Per-plant: a refinery generates $2–10M/day gross margin; IEC 61511 SIS-trip-loss on forced shutdown.
- Deepwater Horizon = $61B single-incident anchor.
- ~700 refineries globally, ~70k IEC-61511 chemical/process plants.
- Regulator forced stand-down cost per plant at $1-5M/day × 30 days × 10% of fleet = $30-150B.
**Comparison** ("Billions per plant"): **agrees** per-plant; fleet-wise underestimated.

---

## Tier A

### nuclear-iec61513
**Revised $ impact**: $30B – $100B (medium confidence).
**Drivers**:
- US reactor fleet: 94 operating reactors; typical reactor generates $1-2M/day gross margin. Fleet-wide CAL-forced stand-down = $100–200M/day.
- NRC CAL precedent: San Onofre Units 2/3 ran ~18 months under CAL → unit-owner losses ~$1B each.
- Replacement cost: I&C refresh is $50-100M per unit × fleet = $5-10B engineering alone.
**Comparison** ("Hundreds of billions"): **overestimated**. Realistic envelope is $30–100B absent a full fleet-decommission scenario.

### oilrig-bop-mux
**Revised $ impact**: $10B – $80B (medium confidence).
**Drivers**:
- Deepwater Horizon single-incident = $61.6B. [BP]
- Global offshore rig fleet ~700 units; deepwater rig day-rate $400–600k/day.
- BSEE-forced stand-down of one deepwater region (GoM) = $50M/day.
- Kinetic tail: another Macondo is a $60B event.
**Comparison** ("Tens of billions"): **agrees**.

### medical-device-fda
**Revised $ impact**: $20B – $100B (medium confidence).
**Drivers**:
- FDA 524B covers ~6000 active connected device clearances (2024); ~14M implanted cardiac devices worldwide.
- Precedent: Medtronic ICD recall (816k devices, 2 deaths) ongoing; prior Fidelis lead settlement $268M for 9k cases. [FDA recalls]
- Litigation per harmed patient $50-200k; mass-recall arithmetic: 10M devices × $200-500 re-cert/replace = $2-5B; hospital revenue-loss from deferred procedures likely 5-10x direct.
**Comparison** ("Tens of billions"): **agrees** low-end; $100B if litigation tail blooms.

### avionics-arinc665
**Revised $ impact**: $80B – $300B (medium confidence).
**Drivers**:
- Global commercial fleet: ~27,000 airframes; avg $150k/day grounding cost per plane. [IBA aero](https://www.iba.aero/resources/articles/the-direct-cost-of-grounding-the-boeing-737-max-8-fleet/)
- 737 MAX anchor: one model, $80B. Multi-model event across ARINC 665 LSAP chain = 4–5× that.
- FAA/EASA Type-Cert re-validation timeline: months to year; fleet ground-cost @ $4B/day theoretical max.
**Comparison** ("Hundreds of billions"): **agrees**.

### pipeline-api1164
**Revised $ impact**: $20B – $100B (medium confidence).
**Drivers**:
- Colonial Pipeline single-day = $420M economic. [Barracuda]
- US liquids pipeline fleet ~220k miles; gas ~3M miles. Coordinated API-1164 forgery → multi-pipeline outage.
- PHMSA-forced SD-02C equivalent: ~$1B/day US-wide.
**Comparison** ("Tens of billions"): **agrees**.

### shim-uefi / authenticode-pe
**Revised $ impact**: $200B – $1T combined (medium confidence).
**Drivers**:
- Installed base: ~1.5B Windows PCs, ~300M business endpoints; every UEFI-Secure-Boot-enabled device.
- CrowdStrike-2024 precedent: single-faulty-update, 8.5M Windows devices, $5.4B Fortune-500 direct, tens-of-billions total. [Fortune](https://fortune.com/2024/08/03/crowdstrike-outage-fortune-500-companies-5-4-billion-damages-uninsured-losses/)
- Authenticode/shim break = CrowdStrike × 10-100× (kernel-level persistence globally, including healthcare $1.9B sector share, banking $1.4B).
**Comparison** ("Hundreds of billions"): **agrees**; probably the single highest-confidence $ estimate in the catalog.

### swift-financial
**Revised $ impact**: $300B – $2T (medium confidence).
**Drivers**:
- Annual flow: $150T across SWIFT. [SWIFT FIN Traffic](https://www.swift.com/about-us/discover-swift/fin-traffic-figures)
- Worst-case isn't theft; it's interbank rail stoppage during crypto rollover. $150T/365 = $410B/day of settlement at risk.
- Precedent: 2016 Bangladesh Bank SWIFT heist $81M was point-attack; system-wide auth break is many orders larger.
- Fraud surge window even at 0.1% capture = $150B/yr.
**Comparison** ("Trillions"): **agrees** as cumulative-across-years; low-trillions is plausible peak.

### fix-cme-exchange
**Revised $ impact**: $200B – $1T (low confidence).
**Drivers**:
- CME alone clears ~$1 quadrillion/yr notional; equity/FX FIX flows $5-10T/day globally.
- Precedent: Knight Capital 2012 $440M single-firm bug; system-wide auth forgery is market-structure event.
- Circuit-breaker stop-trading for days costs market makers $100s of millions; systemic event trillions.
**Comparison** ("Trillions"): **overestimated** as direct loss; correct as notional-at-risk.

### emv-payment-cards
**Revised $ impact**: $50B – $150B (high confidence).
**Drivers**:
- Installed base: 14.7B EMV cards globally (2024). [EMVCo](https://www.emvco.com/news/emvco-reports-nearly-13-billion-emv-chip-cards-in-global-circulation/)
- Reissuance cost: $3–5 per card card-scheme-wide × 14.7B = $44-74B floor.
- Precedent: Target 2013 breach $200M+ direct for 40M cards (~$5/card). MasterCard/Visa EMV migration itself cost US issuers >$8B.
- Fraud surge during rollover window: card-present fraud in US ~$5B/yr; 5-10x during transition = $25-50B.
**Comparison** ("Hundreds of billions"): **slightly overestimated**; $50-150B is tighter.

### pos-pci-pts
**Revised $ impact**: $30B – $100B (medium confidence).
**Drivers**:
- ~120M active POS terminals globally, $200-500 per terminal refresh → $24-60B hardware.
- PIN exposure triggers card-reissuance (see EMV entry): additional $50B.
**Comparison** ("Tens of billions"): **agrees**.

### ibm-icsf-mainframe
**Revised $ impact**: $100B – $500B (medium confidence).
**Drivers**:
- IBM Z runs ~68% of enterprise transaction workloads globally by value; ICSF/Crypto Express wraps core banking keys for top-10 global banks.
- Core-banking ledger signature forgery is existential to affected banks; JPMC/BofA/Citi Tier-1 bank daily throughput $5-10T each.
- Replacement: Crypto Express card refresh $50-100k/unit × ~50k units = $2-5B hardware, but downtime cost is what dominates.
**Comparison** ("Trillions"): **overestimated** for direct damage; correct as notional-at-risk.

### sap-netweaver-sso
**Revised $ impact**: $200B – $1T (medium confidence).
**Drivers**:
- 77% of world transaction revenue touches SAP, $16T consumer purchases. [SAP]
- GL-integrity compromise = financial-restatement event per affected Fortune 500 company; Sarbanes-Oxley material-weakness filings cascade.
- Precedent: NotPetya took Merck's SAP offline for days at $670M cost; scale to simultaneous compromise of F500 SAP estates.
**Comparison** ("Trillions"): **slightly overestimated** for 1-year envelope; correct as multi-year cumulative.

### windows-dpapi
**Revised $ impact**: $100B – $500B (medium confidence).
**Drivers**:
- Installed base: every Windows domain-joined machine (~1.5B PCs + server estate).
- Retroactive decryption of BitLocker recovery keys, browser passwords — essentially a universal credential-dump event for Windows.
- Precedent: Equifax ($1.4B, 147M records) × 10 for breadth, × 10 for depth of data.
**Comparison** ("Hundreds of billions"): **agrees**.

### kubernetes-kubeadm / jwt-libjwt
**Revised $ impact**: $100B – $500B combined (medium confidence).
**Drivers**:
- Cloud IT spend 2024: $855B globally. [Holori]
- JWT RS256 gates OAuth/OIDC/K8s SA/AWS Cognito/Azure AD/GCP IAM — public keys by-design published.
- Precedent: CrowdStrike-2024 $5.4B direct was one endpoint-tool; auth-layer forgery is upstream of every SaaS.
- Reissue cost minimal, but dwell-time fraud during rotation enormous.
**Comparison** ("Hundreds of billions"): **agrees**.

### aws-iot-device-certs
**Revised $ impact**: $30B – $100B (low confidence).
**Drivers**:
- ~15B active IoT devices, ~1–2B on AWS IoT Core.
- Replacement: $0.10-$1 per device re-provisioning × 1B = $100M-$1B direct; but fleet-operational outage dominates.
- Precedent: Mirai botnet economic damage estimates $110M+ per-incident, generalize to auth-break.
**Comparison** ("Tens of billions"): **agrees**.

### esim-gsma
**Revised $ impact**: $20B – $80B (low confidence).
**Drivers**:
- ~1B eSIM devices shipped cumulative by 2024; GSMA RSP CI is RSA-rooted.
- Replacement: carrier re-provisioning cost $5–15/device × 500M actively-used = $2-8B direct; roaming-fraud dwell-time larger.
**Comparison** ("Tens of billions"): **agrees**.

### submarine-cable-slte
**Revised $ impact**: $100B – $1T per day sustained (medium confidence).
**Drivers**:
- 99% of intercontinental internet traffic on submarine cables; >$10T/day financial transactions flow over them. [UN](https://news.un.org/en/story/2026/02/1166867)
- Precedent: 2008 Mediterranean cable cut, regional internet ~70% drop for days; economic spike in hundreds of millions.
- SLTE (line-terminating equipment) firmware-sig forgery = ability to DoS or MitM trunk lines.
- Repair ship mobilization $1M/day × months if physical cuts compound.
**Comparison** ("Tens of billions"): **underestimated**. Daily financial-rail traffic alone is multi-trillion; $100B-$1T is more realistic sustained.

### aerospace-ccsds
**Revised $ impact**: $10B – $50B (low confidence).
**Drivers**:
- Global satcom market ~$300B/yr; CCSDS covers civil/military command-auth.
- Single-satellite loss: $100M-$1B capital + mission-value; constellation-wide auth-break theoretical (Starlink, OneWeb, NavStar) is unprecedented.
**Comparison** ("Tens of billions"): **agrees** low-end.

### piv-cac-smartcard
**Revised $ impact**: $5B – $30B (medium confidence).
**Drivers**:
- Installed base: ~8.5M DoD CAC + federal PIV cards.
- Card reissuance: ~$80–150/card × 8.5M = $680M-$1.3B hard cost.
- Plus enterprise contractor-productivity hit during fallback-auth period: $1-10B.
- Precedent: OPM 2015 breach direct cost ~$350M, cleanup years.
**Comparison** ("Tens of billions"): **agrees** upper; realistic bound $5–30B.

### iso15118-ev-charging / evse-iso15118-pnc
**Revised $ impact**: $5B – $30B (low confidence).
**Drivers**:
- Public charging points globally: ~5.5M (2024), ~1.3M added 2024. [IEA](https://www.iea.org/reports/global-ev-outlook-2025/electric-vehicle-charging)
- PnC deployment still partial (~10–20%); per-station cert refresh ~$50.
- Fraud surge on free-charging exploitation: real but bounded.
- Grid-stability tail-risk if coordinated V2G manipulation: could be catastrophic but low-probability.
**Comparison** ("Tens of billions"): **agrees** high-end.

### john-deere-agtech
**Revised $ impact**: $5B – $30B (low confidence).
**Drivers**:
- US corn/soy harvest timing ~$150B/yr crop value; coordinated signed-firmware attack during narrow harvest window = multi-week yield loss.
- Deere fleet: ~2M connected combines/tractors; firmware-refresh impractical mid-season.
**Comparison** ("Tens of billions"): **agrees**.

### epassport-icao
**Revised $ impact**: $20B – $100B (medium confidence).
**Drivers**:
- Installed base: >1B ePassports in circulation, 180 countries issue. [Signicat]
- Reissuance: $50-150 per passport × 500M affected = $25-75B hard cost.
- Border-outage cost: tourism sector global $1-2T/yr; 5% disruption for 30 days = $50-100B.
- Precedent: COVID-era border closures hit tourism $1T+.
**Comparison** ("Tens of billions"): **agrees** low-end; $50-100B more realistic.

### fido2-webauthn
**Revised $ impact**: $30B – $150B (medium confidence).
**Drivers**:
- Installed base: >billion FIDO2 accounts; enterprise attestation policies at DoD/Google/Microsoft.
- Attack is limited to attestation-enrollment, not per-credential (ECDSA).
- Precedent: MFA-bypass incidents (0ktapus 2022) cost >$100M per victim; generalize.
**Comparison** ("Hundreds of billions"): **overestimated**; per-credential keys survive, so blast bounded.

### rpki-routinator / dnssec-bind9
**Revised $ impact**: $50B – $500B per day of sustained outage.
**Drivers**:
- DNS/BGP are planetary-scale; Facebook Oct-2021 6-hour BGP outage cost ~$100M. Globalize.
- $10T/day flows through the internet routing/naming layer. [Federal Reserve]
- Precedent: Dyn 2016 DNS attack caused ~$110M economic loss for 2 hours.
**Comparison** ("Hundreds of billions / Trillions"): **agrees**.

### kerberos-pkinit
**Revised $ impact**: $100B – $500B (medium confidence).
**Drivers**:
- Couples to ADCS entry; PKINIT is the smartcard/Hello for Business auth path.
- Precedent: NotPetya-scale, simultaneously across F500.
**Comparison** ("Hundreds of billions"): **agrees**.

### smime-email (HNDL case)
**Revised $ impact**: $30B – $150B (low confidence).
**Drivers**:
- Retroactive decryption of decades of archived corporate/gov/legal email.
- M&A confidentiality, HIPAA disclosure penalties (~$50k/record × millions of records), DoD CUI spillage.
- Hard to price because damage is incremental over years.
**Comparison** ("Tens of billions"): **agrees**.

### openldap-tls / saml-ruby
**Revised $ impact**: $30B – $150B combined (medium confidence).
**Drivers**:
- Enterprise identity fabric; Okta-2022-style incidents cost $150M+ per customer at scale.
- Precedent: SolarWinds ($100B) is the closest mechanism.
**Comparison** ("Tens of billions"): **slightly underestimated**.

### nss-firefox
**Revised $ impact**: $30B – $100B (medium confidence).
**Drivers**:
- 1.5B Firefox installs + entire RHEL system-crypto stack.
- RHEL runs ~90% of F500 Linux workloads, banks, telcos. MitM of yum/dnf = distro-wide supply chain.
**Comparison** ("Hundreds of billions"): **slightly overestimated**; modern TLS uses ECDHE so forward secrecy survives, narrowing live MitM exposure.

### acme-lets-encrypt
**Revised $ impact**: $10B – $50B (medium confidence).
**Drivers**:
- ~60% of HTTPS (~2B certs). Account-key rotation exists (`certbot update_account`), so recovery faster than one might think.
- Precedent: 2011 DigiNotar revocation cost ~$10M direct + unknown indirect; Lets Encrypt revocation-at-scale unprecedented.
**Comparison** ("Tens of billions"): **agrees**.

### openssh-host-keys
**Revised $ impact**: $20B – $100B (medium confidence).
**Drivers**:
- Every Linux/Unix server on internet; harvest-already-done by Shodan/Censys.
- CI/CD git-push MitM is the highest-value vector (supply-chain code injection).
- Precedent: SolarWinds $100B was one vendor; generalize to arbitrary supply-chain injection.
**Comparison** ("Tens of billions"): **agrees** low-end; $50–100B more realistic given SolarWinds anchor.

---

## Tier B / Tier C sanity checks (where we suspect OOM is wrong)

### atm-xfs-firmware
**Revised $ impact**: $2B – $10B (medium confidence).
**Drivers**:
- Global ATM jackpotting 2024: $20M lost. [TheRecord](https://therecord.media/fbi-atm-jackpotting-2025-report); global ATM fraud $2.4B/yr. [ATMIA]
- Even scaling 10× for crypto-fueled outbreak: $20B ceiling.
- ATM fleet ~3M globally; replacement $2-5k each = $6–15B for full refresh.
**Comparison** ("Tens of billions"): **overestimated**. $2–10B is tighter.

### hbci-fints-banking
**Revised $ impact**: $500M – $5B (medium confidence).
**Drivers**:
- German-only retail banking protocol; ~40M FinTS-enabled users.
- Bounded regional impact.
**Comparison** ("Billions"): **agrees**.

### voting-machine-signing
**Revised $ impact**: $1B – $10B (medium confidence).
**Drivers**:
- US voting-equipment total budget ~$800M federal + state match.
- Primary damage is non-$: election legitimacy; litigation cost order $100M-$1B.
**Comparison** ("Low billions"): **agrees**.

### atsc3-broadcast
**Revised $ impact**: $1B – $10B (low confidence).
**Drivers**:
- ATSC 3.0 deployed in ~80% US metros; TV-set firmware recall if trust roots forged.
- Broadcaster ad-revenue disruption during cutover.
**Comparison** ("Billions"): **agrees**.

### vestas-wind-turbine
**Revised $ impact**: $5B – $30B (medium confidence).
**Drivers**:
- Vestas installed fleet: 189 GW; $/MWh revenue $40-80 × ~400 TWh/yr = $15-30B/yr Vestas-fleet revenue at risk. [Statista Vestas]
- Grid-disconnection mandate by TSO during remediation: significant renewable-generation shortfall.
**Comparison** ("Tens of billions"): **agrees**.

### tpm2-rsa-ek
**Revised $ impact**: $20B – $100B (medium confidence).
**Drivers**:
- Every enterprise-provisioned Windows/Linux device with TPM 2.0 (~1B+ active).
- BitLocker/Intune/MDM attestation chain break; device-replacement cost if EK is ROM.
**Comparison** ("Hundreds of billions"): **slightly overestimated** — per-TPM EK refresh via new endorsement keys is sometimes possible; $20-100B tighter.

### flexlm-license
**Revised $ impact**: $5B – $20B (low confidence).
**Drivers**:
- EDA/CAD/scientific-software publisher revenue ~$30B/yr; license-forgery impacts revenue collection.
- Precedent: software-piracy losses ~$46B/yr (BSA) — a floor.
**Comparison** ("Tens of billions"): **agrees** low-end.

### ipsec-ikev2-libreswan / strongswan
**Revised $ impact**: $10B – $50B (medium confidence).
**Drivers**:
- Enterprise site-to-site VPN fleet ~millions; RSA-auth-only legacy tunnels still prevalent.
- MitM of IPsec → plaintext intra-enterprise traffic; precedent ShadowBrokers EQGRP IKEv1 tooling.
**Comparison** ("Tens of billions"): **agrees**.

### apache-santuario / xmlsec1-xmldsig / pdf-itext
**Revised $ impact**: $10B – $50B combined (low confidence).
**Drivers**:
- Tax/customs e-filing, legal contracts, invoice signing.
- EU eIDAS + HMRC + IRS flows.
- Precedent: Wirecard-scale fraud via forged signatures theoretical; bounded by detectability.
**Comparison** ("Tens of billions"): **agrees**.

---

## Entries with "None direct" / "Negligible" reviewed

- **tor**: v3 unaffected (Ed25519). Agrees.
- **ntp-autokey**: deprecated, no production use. Agrees.
- **mastodon/xmpp/racing-chip-timing**: bounded. Agree negligible.
- **iaea-safeguards**: marked "None direct" for $ but geopolitical axis is high. Agrees.
