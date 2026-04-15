# digital-tachograph-eu — RSA in EU truck driver smart cards

**Regulation:** EU 165/2014; Commission Regulation 2016/799 (Annex IC); EC-MSA (Member State Authority) PKI
**Industry:** Road freight — 6+ million commercial drivers in the EU/EEA/UK/Switzerland
**Algorithm:** RSA-1024 (Gen 1 tachograph, 2006-2019), ECDSA P-256 (Gen 2, 2019+)

## What it does

Every commercial truck over 3.5 tonnes or bus over 9 seats in the EU is legally required
to have a tachograph — a recording device that tracks driving time, rest periods, speed,
and distance. Drivers carry a personal smart card (DF_Tachograph) that stores their
activity across vehicles and is inserted into the tachograph at each work session.

The Gen 1 Digital Tachograph (DT1, 2006 spec, Annex IB of EEC 3821/85) uses RSA-1024 for:

- **Driver card signature**: activity records (speeds, distances, work/rest periods)
  are signed with the driver's RSA-1024 private key on the smart card, produced by
  a Member State Authority (MSA) like Bundesamt für Güterverkehr (DE), DVSA (UK),
  Dekra (also DE), etc.
- **Vehicle Unit (VU) signature**: the tachograph itself has an RSA-1024 keypair
  used to sign the VU's data downloads (DDD files)
- **Company card signature**: fleet operators have RSA-1024 cards used to lock
  the VU and download data
- **Workshop card signature**: calibration workshops have RSA-1024 cards used to
  calibrate and seal the VU
- **Trust chain**: MSA -> European Root Certificate Authority (ERCA) at JRC Ispra
  (Italy). ERCA signs MSA certs; MSAs sign driver/VU/company/workshop cards.

Gen 2 (Smart Tachograph / DT2, 2019+) moved to ECDSA P-256. But Gen 1 cards are still
valid until their 5-year expiry — and both Gen 1 DT + Gen 1 cards remain in legal use
across EU fleets well into the late 2020s for cards issued before 2023.

Tachograph records are the primary enforcement basis for EU driving-time regulation
(561/2006), which limits daily driving to 9h (10h twice per week), weekly to 56h,
fortnightly to 90h, with mandatory rest periods. Roadside inspections by DVSA,
Gendarmerie, BAG, etc. check the smart card + VU signatures on site.

## Why it's stuck

- Gen 1 tachographs have a 15-year service life mandate. Units installed in 2018 are
  still compliant until 2033 and use RSA-1024 throughout. Replacement is triggered
  by VU failure or vehicle replacement, not regulatory migration.
- The ERCA Root CA is operated by JRC Ispra (Italian national lab for the EU). It
  is a physical facility with HSM-stored RSA root keys. Re-rooting requires
  coordinated MSA migration across 27 EU states plus EEA/CH/UK bilateral recognition.
- Driver cards are issued for 5 years. Gen 1 cards issued in 2022 remain in driver
  wallets until 2027 — and are legally valid in Gen 1 VUs throughout that window.
- The enforcement ecosystem (roadside inspection devices, company DDD analysis
  software like SITLR, Continental VDO, Stoneridge SE5000 readers, fleet telematics
  like Webfleet/Geotab) must all accept Gen 1 RSA signatures until Gen 1 cards
  expire.

## impact

the tachograph signature is the sole evidence basis for driver working-time compliance
in the EU, and for criminal liability when things go wrong. forge the signature and
you forge driver records.

- factor the ERCA RSA root (published in ERCA bulletins, embedded in every VU).
  now you can issue MSA certs for any "member state" — nonexistent or real. those
  certs let you mint driver cards, VU certs, and workshop cards accepted by every
  Gen 1 tachograph in the EU.
- **driving-time fraud**: forge driver card records to show compliant rest periods
  when the driver actually drove through. current mechanical fraud (magnet on the
  speed sensor, yellow wire on the CAN bus) is detectable; cryptographic forgery
  with a valid signature is not. saves fleets 10-20% on driver costs via illegal
  extension of shifts.
- **accident liability laundering**: after a fatal crash, overwrite the driver's
  card records to show the driver was rested, within hours limits, under speed limits.
  the signature makes the altered record forensically authoritative. Poland, UK,
  Germany all prosecute driving-time offences based on tachograph data — a forged
  record shifts liability.
- **workshop card forgery**: mint workshop cards to "calibrate" tachographs,
  resetting odometer readings, removing fraud detection events, or whitelisting
  modifications. the calibration record is signed and trusted by roadside inspectors.
- **carrier competition**: Polish, Romanian, Czech carriers undercut Western
  European carriers on price by (often illegally) extending drivers' hours. forged
  tachograph compliance normalizes this at scale, undermining the 561/2006
  working-time framework that the EU built specifically to equalize road freight
  competition.
- **bus industry**: the same tachograph regime applies to buses. forged driver
  records allow fatigued bus drivers to pass roadside checks. crashes due to driver
  fatigue already kill hundreds annually in the EU; undermined enforcement
  increases that.
- **cross-border**: UK drivers entering the EU post-Brexit use the same digital
  tachograph standard (UK retained Annex IC). the trust chain extends to ABLE
  (UK DVSA's certifying authority). Swiss and Norwegian drivers too.

## Code

`tacho_rsa_card.c` — `tacho_verify_driver_card()` (verify MSA-issued driver card
against ERCA root RSA-1024), `tacho_sign_activity()` (sign driver activity records
with RSA-1024-SHA-1 per Annex IB §CSM_017), `tacho_download_ddd()` (DDD file
generation with VU signature), `tacho_calibrate()` (workshop card calibration
signature). ERCA trust anchor model and EU Regulation 165/2014 context in comments.
