# eSIM / GSMA SGP.02 — RSA Remote SIM Provisioning

**Source:** GSMA SGP.02 v4.2, SGP.22 v3.0 (public specifications)  
**Reference:** https://www.gsma.com/solutions-and-impact/technologies/esim/  
**Status:** Closed hardware, open specification

## what it does

Every eSIM (embedded SIM) in every phone, tablet, laptop, smartwatch, car, and IoT device uses GSMA's Remote SIM Provisioning architecture. The eSIM chip receives its identity certificate at manufacturing time. Profile downloads from operators (e.g. activating a cellular plan) use RSA/ECDSA mutual authentication between the device and the SM-DP+ server.

## why the hardware lifespan makes this uniquely bad

- eSIM identity certificates are burned into the secure element at **manufacturing time**. They cannot be updated via OTA. There is no firmware update path for the cryptographic identity.
- **Automotive eSIMs**: cars manufactured today have a 15-year lifespan. Their RSA eSIM keys will still be in use in 2039+, potentially 7+ years after a CRQC exists.
- **Industrial IoT**: gas meters, utility sensors, asset trackers — 10-20 year deployment lifespans. Tens of millions of devices with immutable RSA identities.
- **Medical devices**: RSA keys in implantable devices, infusion pumps, remote patient monitoring — cannot be "recalled for crypto upgrade."
- Attack surface: GSMA publishes a directory of eUICC public keys. Forge any device's identity → impersonate it to any carrier → provision rogue profiles → OTA firmware attacks.

## migration status

GSMA published post-quantum guidelines (PQ.03). eSIM spec update for PQC is in discussion. Irrelevant for any device already manufactured.
