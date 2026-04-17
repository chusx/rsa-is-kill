# avionics-arinc665 — RSA in aircraft loadable software signing (ARINC 665 / DO-178C)

**Repository:** ARINC 665-3 specification (AEEC); OEM implementations (Airbus/Boeing, proprietary) 
**Industry:** Commercial aviation — Airbus, Boeing, every airline globally 
**Algorithm:** RSA-2048 (aircraft software part signing per ARINC 665-3 Part 7; Jeppesen navigation database) 

## What it does

ARINC 665 defines the standard for loading software onto aircraft avionics Line Replaceable
Units (LRUs). DO-178C (avionics software standard) requires integrity verification for any
software loaded onto flight-critical avionics. In practice, this means RSA-2048 signatures
on every software package loaded onto every aircraft avionics unit.

This covers:
- FMS (Flight Management System) software and navigation databases
- IRS/ADIRU (Inertial Reference System) firmware
- Engine FADEC software updates (Full Authority Digital Engine Control)
- Radar, TCAS, ADS-B, ACARS software
- Jeppesen navigation database updates (28-day AIRAC cycle, every airline worldwide)

The Jeppesen NavDB is particularly important: every FMS-equipped aircraft in the world
(roughly 50,000 commercial and business aircraft) installs Jeppesen NavDB updates every
28 days. Each update is signed with Jeppesen/Boeing's RSA-2048 key and verified by the
FMS before the database is loaded.

The Aircraft Data Loading Unit (ADLU) or Portable Data Loading Unit (PDLU) verifies the
RSA signature before loading any software. The OEM CA cert (Airbus, Boeing, or avionics
OEM like Honeywell, Collins Aerospace) is burned into the ADLU at manufacture.

## Why it's stuck

- Avionics software follows DO-178C / DO-278A qualification. Any change to the signing
 algorithm requires re-certification of the loading unit software, the verification logic,
 and potentially the avionics LRU itself. This is a multi-year, multi-million-dollar process
 per aircraft type.
- ARINC 665-3 is maintained by AEEC (Airlines Electronic Engineering Committee). Revisions
 are slow; the 665-3 update took years. A 665-4 with non-RSA provisions would take another
 full committee cycle, then implementation, then certification.
- The OEM CA cert is burned into ADLU hardware at manufacture. Updating it for existing
 ADLUs requires a hardware modification or replacement, which requires an airworthiness
 directive (FAA, EASA) for fielded aircraft.
- Jeppesen NavDB is the world's most-deployed avionics database. Changing its signing
 algorithm requires simultaneous updates to every FMS that verifies NavDB signatures —
 every aircraft in the fleet, globally, before the transition.

## impact

aircraft software signing is the gate between "authorized avionics software" and "whatever
you can get installed on a flight computer." the RSA key is what makes that gate meaningful.

- Jeppesen RSA-2048 signing key: used for NavDB updates installed on every commercial aircraft
 in the world every 28 days. the OEM public key is in every Jeppesen NavDB update package
 (embedded in the SWP header) and in every ADLU/PDLU's cert store. factor it. sign a modified
 NavDB with incorrect waypoints, modified ILS frequencies, or altered approach procedures.
 any aircraft FMS that accepts Jeppesen NavDB updates (all of them) will accept your data.
- FADEC software signing: FADEC is the computer that controls engine thrust. it's loaded via
 ARINC 665. the engine OEM (GE, Rolls-Royce, P&W) signs FADEC software with RSA-2048.
 factor the OEM signing key. load modified FADEC software that changes engine behavior.
 this is in the same threat model as Stuxnet for centrifuges — software modification via
 forged signatures on safety-critical controllers.
- "but there are other safety systems." yes. flight crew, redundant systems, TCAS, QAR.
 a forged navDB by itself probably doesn't crash a plane. but it contributes to the
 conditions that make accidents more likely, and it's undetectable because the signature
 checks pass. the DO-178C certification assumed the signing key was secure.
- EFB (Electronic Flight Bag) software signing: pilots use EFBs for charts, performance
 data, aircraft systems manuals. EFB software is ARINC 665-signed. compromised EFB
 software shows wrong performance data during takeoff calculations.

## Code

`arinc665_rsa.c` — `arinc665_verify_software()` (RSA-2048 PKCS#1 v1.5 verify on ARINC 665
SWP image, X.509 cert chain to OEM CA), `jeppesen_navdb_verify()` (RSA-2048 Jeppesen NavDB
signature verification). DO-178C DAL classification context, FADEC and ADIRU LRU types,
28-day NavDB cycle and global fleet implications in comments.
