# aerospace-ccsds — RSA in spacecraft command authentication

**Standard:** CCSDS 351.0-M-1 (Space Data Link Security) / CCSDS 350.9-G-3 
**Industry:** Space agencies (NASA, ESA, JAXA, ISRO, DLR, CNSA) and commercial satellites 
**Algorithm:** RSA-2048/3072 (OAEP key wrap), ECDSA P-256/P-384 (signatures) 

## What it does

CCSDS is the communication standard for virtually all spacecraft. SDLS (Space
Data Link Security) protects command uplinks to prevent unauthorized commanding
of spacecraft.

The key management uses RSA-OAEP to wrap AES-256 session keys. The spacecraft
stores the ground station's RSA-2048 public key in EEPROM, burned at
integration before launch. When the ground needs to update the session key,
it wraps the new key with the spacecraft's RSA public key and uplinks it.

Once the spacecraft adopts the attacker's session key (after classical factoring
recovers the RSA private key), the attacker can authenticate arbitrary
telecommands: attitude maneuvers, payload power, transponder reconfiguration,
or destructive commands.

## Why it's stuck

- **Hardware is in orbit**: spacecraft EEPROM cannot be updated remotely
- **Launch schedule**: a satellite launched today will be commanded with the
 same RSA-2048 public key until decommission (5-30 years)
- **CCSDS spec gap**: no non-RSA algorithm profile in CCSDS 351.0-M-1
- **Ground station systems**: DSN (NASA), ESTRACK (ESA), JAXA ground systems
 would all need updates before any spacecraft could use non-RSA

Mission-critical targets: weather satellites (GOES-R, Meteosat), Earth
observation (Sentinel, Landsat), science missions (James Webb, Hubble servicing
was RSA-era), ISS commanding infrastructure.

## impact

no patch tuesday in orbit. the spacecraft launched last year with RSA-2048 keys burned into EEPROM will be flying until 2040+, and there is literally no mechanism to update those keys remotely. once you factor the RSA key, you own the uplink.

- forge a key transfer packet, get your session key accepted, then send arbitrary telecommands: power off transponders, vent propellant, put the satellite in safe mode permanently. dead satellite, no physical access required
- forge attitude control or thruster commands and change the orbit. collision risk with other satellites or the ISS, and yes this applies to operational weather and science satellites
- GOES-R does US weather forecasting. Copernicus Sentinel does EU earth observation. forge commands that corrupt instrument calibration and suddenly the downstream data (climate models, GPS corrections, aviation weather) is quietly wrong in ways nobody notices for a while
- to update the RSA key you have to authenticate with the current RSA key. so there's no way to patch your way out once the factoring break shows up. it's keys all the way down
## Code

`ccsds_sdls_rsa_auth.c` — `ccsds_sdls_wrap_session_key()` showing RSA-OAEP-2048
session key wrapping per CCSDS 350.9 §3.6, and the a factoring attack scenario
(factor spacecraft public key → forge Key Transfer Packet → control spacecraft).
