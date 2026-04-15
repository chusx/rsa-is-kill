# ipaws-cap-alerts — RSA in US emergency alerting (WEA, EAS, NOAA Weather Radio)

**Standard:** FEMA IPAWS-OPEN CAP Profile v1.0; OASIS CAP v1.2; ITU-R BT.1836 (int'l)
**Industry:** Public safety — National Weather Service, FEMA, state/local EOCs, broadcasters
**Algorithm:** RSA-2048 (IPAWS digital signature on CAP alerts; XMLDSig rsa-sha256)

## What it does

IPAWS (Integrated Public Alert & Warning System) is FEMA's alert routing backbone. It
takes Common Alerting Protocol (CAP) v1.2 XML messages from ~1,500 authenticated
"alerting authorities" (state emergency managers, NWS forecast offices, tribal nations,
some federal agencies) and distributes them to:

- **WEA** (Wireless Emergency Alerts) — the push alerts on every US cellphone
- **EAS** (Emergency Alert System) — TV, AM/FM radio, cable interrupts
- **NWR** (NOAA Weather Radio) — the ~1,000 transmitters providing 24/7 weather alerts
- **IPAWS-OPEN public feed** — consumed by Google Public Alerts, Apple Weather, etc.

Every CAP alert entering IPAWS is signed XMLDSig with an RSA-2048 key issued to the
alerting authority by FEMA. The Master Endpoint (MEP) verifies the signature before
forwarding. Each CAP alert carries:

- A signed `<alert>` block with `<info>` payload (text, urgency, severity, area)
- A `<Signature>` element with `<SignatureValue>` (RSA-2048) and the authority's cert
- A FEMA trust anchor in the verifier chain

Alerting authority RSA keys are issued via the IPAWS PIN program after a background
investigation. Keys are typically stored on HSMs at 911 call centers or EOCs.

## Why it's stuck

- IPAWS CAP Profile v1.0 (2009, minor updates through 2022) specifies `rsa-sha256`
  XMLDSig. No new algorithm is in the FEMA IPAWS roadmap.
- The IPAWS trust store is baked into every EAS encoder/decoder (Sage, Digital Alert
  Systems / DASDEC, Trilithic) and every cellphone carrier's CMAS gateway. Field
  update of EAS boxes is slow: many are rack-mounted appliances with vendor-only
  firmware updates, deployed at 30,000+ EAS participants nationwide.
- The FCC Part 11 rules on EAS reference IPAWS authentication by regulation.
  Changing the algorithm requires NPRM rulemaking at the FCC.
- Alerting authority keys are typically 2-year certificates; rotation happens but
  the algorithm is locked in by the IPAWS profile.

## impact

IPAWS is the only path for authenticated emergency alerts to TV, radio, and every
phone in the US. forge the signature and you forge presidential-level alerts.

- factor the IPAWS Master Endpoint's RSA-2048 signing key or the FEMA IPAWS CA key.
  now you can issue signed CAP alerts from any authority's identity.
- **WEA abuse**: send a forged Imminent Threat alert to every phone in a geographic
  polygon. phones vibrate with "Civil Emergency" or "Evacuation Immediate". the
  2018 Hawaii false alert was one county EOC accidentally sending one. a factoring
  attack does this at will, with perfect signatures, from any authority.
- **EAS attention signal + voice**: the EAS activation tone interrupts every TV and
  radio in an area. a forged Presidential Alert (CIV / EAN event code) cannot be
  overridden by broadcasters; every licensee is FCC-mandated to forward it. broadcast
  any audio the attacker wants to every household in the target area.
- **evacuation and counter-evacuation attacks**: forge evacuation orders to move people
  into harm's way, or cancel real evacuation orders during a hurricane / wildfire.
  people have died from false emergency information before (2003 San Diego Cedar Fire,
  2018 Camp Fire evacuation confusion). authenticated forged alerts are worse than any
  of that.
- **market manipulation**: a forged Hazmat alert for a chemical plant county crashes
  regional stocks. a forged nuclear-event alert at a reactor operator causes utility
  sector panic. the 2013 AP Twitter hack moved markets off a single fake tweet;
  a nationally broadcast forged Presidential Alert does more.
- **cascading to international**: IPAWS alerts flow to international wire services
  and Google Public Alerts. the reach extends beyond US borders within seconds.
- Canada's NAAD System and EU-ALERT use equivalent CAP-over-TLS-with-RSA architectures
  and have similar exposure; IPAWS is the most target-rich because of scale.

## Code

`ipaws_cap_sign.py` — `sign_cap_alert()` (XMLDSig-Enveloped RSA-2048-SHA-256 signature
over CAP alert XML), `verify_cap_alert()` (verify against IPAWS trust chain),
`build_wea_alert()` (construct WEA-profile CAP alert with CMAC parameters),
`build_eas_same()` (SAME header for EAS activation). FEMA IPAWS PIN authority model and
CAP v1.2 profile constraints in comments.
