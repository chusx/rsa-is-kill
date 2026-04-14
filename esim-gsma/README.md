# eSIM / GSMA SGP.02 — RSA Remote SIM Provisioning

**Source:** GSMA SGP.02 v4.2, SGP.22 v3.0 (public specifications)  
**Reference:** https://www.gsma.com/solutions-and-impact/technologies/esim/  
**Status:** Closed hardware, open specification

## what it does

Every eSIM (embedded SIM) in every phone, tablet, laptop, smartwatch, car, and IoT device uses GSMA's Remote SIM Provisioning architecture. The eSIM chip receives its identity certificate at manufacturing time. Profile downloads from operators (e.g. activating a cellular plan) use RSA/ECDSA mutual authentication between the device and the SM-DP+ server.

## impact

eSIM identity certificates are burned into the secure element at manufacturing time. there is no OTA update path for the cryptographic identity itself. whatever RSA key was baked in at the factory is the key forever.

- automotive eSIMs: cars manufactured today have 15-year lifespans. those RSA eSIM keys will still be in use in 2039+, potentially 7 years after a CRQC exists
- industrial IoT: gas meters, utility sensors, asset trackers with 10-20 year deployment lifespans. tens of millions of devices with permanently immutable RSA identities
- medical devices: RSA keys in implantable devices, infusion pumps, remote patient monitoring. you can't do a recall for a crypto upgrade on a pacemaker
- GSMA publishes a directory of eUICC public keys. forge any device identity, impersonate it to any carrier, provision rogue profiles, and you have a path to OTA firmware attacks on the device itself
## migration status

GSMA published post-quantum guidelines (PQ.03). eSIM spec update for PQC is in discussion. Irrelevant for any device already manufactured.
