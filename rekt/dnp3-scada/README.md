# dnp3-scada — RSA-1024 in power grid SCADA

**Standard:** IEEE Std 1815-2012 (DNP3) Annex A — Secure Authentication Version 5 (SAv5) 
**Industry:** Electric power distribution, water/wastewater, oil & gas pipelines 
**Algorithm:** RSAES-OAEP-1024 (asymmetric Update Key transport) 

## What it does

DNP3 (Distributed Network Protocol 3) is the dominant SCADA communication
protocol for electric utility substations, water treatment, and pipeline control
in North America. Secure Authentication Version 5 (SAv5) provides message
authentication between SCADA Masters and Remote Terminal Units (RTUs)/
Intelligent Electronic Devices (IEDs).

The SAv5 key establishment protocol uses **RSA-1024 with OAEP** to wrap a
symmetric Update Key. The Update Key is then used for HMAC-SHA256 message
authentication. The asymmetric portion (key wrap) uses 1024-bit RSA —
classically deprecated since ~2013 (NIST SP 800-131A).

Key facts:
- RSA-1024 key size: mandated in SAv5 spec (IEEE 1815-2012 Annex A §A.8)
- DNP3 devices: RTUs, IEDs at substations, pump stations, pipeline RTUs
- Device lifespan: 15-30 years (many SAv5 devices deployed 2010-2020 still operating)
- OTA firmware updates: rare to nonexistent for field devices
- SAv6 (draft): proposes TLS but does not specify non-RSA

## Why it's stuck

1. RSA-1024 is in the published spec — changing requires a new IEEE standard
2. RTUs and IEDs are specialized hardware with fixed firmware cryptography
3. Utilities must certify new firmware with NERC CIP auditors
4. Many utilities run a mix of SAv3 (no auth), SAv5 (RSA-1024), and no SAv6
5. NERC CIP compliance timelines are measured in years

Harvest-Now-Decrypt-Later risk: adversaries recording SAv5 key establishment
traffic today can later recover Update Keys via RSA-1024 factoring,
gaining ability to forge arbitrary SCADA commands (open/close breakers,
change setpoints, disable protection relays).

## impact

DNP3 SAv5 protects RTUs at substations, pump stations, and pipeline compressor stations. also, the mandated key size is RSA-1024, which is already classically weak. this is not just a future factoring break problem.

- open circuit breakers at substations to cause targeted power outages. specific neighborhoods, hospitals, data centers, whatever you feel like
- forge trip commands to protective relays and damage transformers by switching them incorrectly. large power transformers have 12-18 month lead times. you can cause multi-month outages
- pipeline: forge compressor setpoints, create overpressure events, potential pipeline rupture
- water: forge pump commands, drain or overpressure distribution systems
- RSA-1024 is already classically broken with sufficient compute. HNDL-captured SAv5 traffic from years ago is retroactively attackable today without any factoring break at all
## Code

`dnp3_sav5_rsa_auth.c` — `dnp3_sav5_wrap_update_key()` showing RSAES-OAEP-1024
key wrap per SAv5 §A.8 and the `SAv5_KeyStatusResponse` struct with
`key_wrap_algo = 0x0005` (RSAES-OAEP-1024).
