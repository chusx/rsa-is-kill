# dnp3-scada — RSA-1024 in power grid SCADA

**Standard:** IEEE Std 1815-2012 (DNP3) Annex A — Secure Authentication Version 5 (SAv5)  
**Industry:** Electric power distribution, water/wastewater, oil & gas pipelines  
**Algorithm:** RSAES-OAEP-1024 (asymmetric Update Key transport)  
**PQC migration plan:** None — no PQC algorithm in DNP3 SAv5 or SAv6 draft

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
- SAv6 (draft): proposes TLS but does not specify PQC

## Why it's stuck

1. RSA-1024 is in the published spec — changing requires a new IEEE standard
2. RTUs and IEDs are specialized hardware with fixed firmware cryptography
3. Utilities must certify new firmware with NERC CIP auditors
4. Many utilities run a mix of SAv3 (no auth), SAv5 (RSA-1024), and no SAv6
5. NERC CIP compliance timelines are measured in years

Harvest-Now-Decrypt-Later risk: adversaries recording SAv5 key establishment
traffic today can later recover Update Keys via CRQC RSA-1024 factoring,
gaining ability to forge arbitrary SCADA commands (open/close breakers,
change setpoints, disable protection relays).

## why is this hella bad

DNP3 SAv5 protects RTUs at substations, pump stations, and pipeline compressor stations. Breaking authentication means:

- **Open circuit breakers at substations** → targeted power outages (specific neighborhoods, hospitals, data centers)
- **Forge trip commands to protective relays** → damage transformers by switching them incorrectly → months-long outages (large power transformers have 12-18 month lead times)
- **Pipeline**: forge compressor setpoints → overpressure events → potential pipeline rupture or explosion
- **Water**: forge pump enable/disable commands → drain or overpressure distribution systems

RSA-1024 is the key size — already classically broken with sufficient resources. A nation-state adversary with classical compute may not even need a CRQC to attack older SAv5 deployments. Stored HNDL traffic from RSA-1024 sessions is already retroactively attackable today.

## Code

`dnp3_sav5_rsa_auth.c` — `dnp3_sav5_wrap_update_key()` showing RSAES-OAEP-1024
key wrap per SAv5 §A.8 and the `SAv5_KeyStatusResponse` struct with
`key_wrap_algo = 0x0005` (RSAES-OAEP-1024).
