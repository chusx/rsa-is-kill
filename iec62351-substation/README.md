# iec62351-substation — RSA in power substation protection (IEC 61850 GOOSE/MMS)

**Repository:** libIEC61850 (mz-automation/libIEC61850), OpenIEC61850; ABB/Siemens/SEL IED firmware  
**Industry:** Electric power grid — transmission substations, NERC CIP regulated  
**Algorithm:** RSA-2048 (IED TLS certificates per IEC 62351-3; GOOSE trip signatures per IEC 62351-5)  
**PQC migration plan:** None — IEC 62351 is maintained by IEC TC57/WG15; no PQC work item published; last major revision was 62351-5:2020 and it specifies RSA/ECDSA with no PQC mention

## What it does

IEC 61850 is the protocol stack for modern power substation automation. It covers MMS
(control and configuration over TCP) and GOOSE (protection relay coordination over
Ethernet multicast). A GOOSE "trip" message tells a circuit breaker to open in under 4ms —
this is how protection relays coordinate fault isolation on transmission lines.

IEC 62351-3 adds TLS to MMS connections. The IED (Intelligent Electronic Device —
protection relay, bay controller, merging unit) presents an RSA-2048 certificate during
the MMS TLS handshake. IEC 62351-5 adds RSA or ECDSA signatures to GOOSE frames to
prevent unauthorized trip injection.

The IED public keys are distributed via the Substation Configuration Description (SCD)
file — an XML document that describes the entire substation's configuration and is
stored on the substation engineering workstation. It's the CRQC input document.

Deployed in:
- Every new high-voltage substation built since ~2010 in Europe and North America
- ABB REL series, Siemens SIPROTEC, GE D30/D60, SEL-400 series protection relays
- ENTSO-E member TSOs (Elia, RTE, National Grid, TenneT, etc.)
- US bulk electric system (NERC CIP-007, CIP-010 in scope)

## Why it's stuck

- IED firmware update cycles in substations are 5-10 years. Utilities have strict
  change management; a firmware update on a 500kV protection relay requires outage
  planning, testing, and regulator notification (NERC CIP).
- IEC 62351-5 GOOSE signing has a 4ms latency budget. RSA-2048 signing on a
  Cortex-A9 (typical IED) takes ~1ms, leaving 3ms margin. RSA verification on the
  receiving side adds another ~1ms. Many deployments have GOOSE signing disabled
  because the timing budget is too tight. Switching to something like SLH-DSA would
  make this worse — 10-50ms signing latency would blow the protection timing window.
- The SCD-based key distribution infrastructure is complex to operate. Many utilities
  deployed IEC 61850 without enabling the security features — IEC 62351 is "security
  profile" on top of the base protocol and is optional at the vendor level.
- IEC TC57/WG15 has not published any post-quantum guidance or work item for IEC 62351.

## impact

GOOSE is what causes circuit breakers to trip on transmission lines. unauthorized GOOSE
trips cause blackouts. authorized GOOSE trips being ignored also causes blackouts (and fires).

- factor the IED's RSA-2048 TLS cert (from any MMS TCP capture on the substation LAN,
  or from the SCD file which lives on the engineering workstation). MitM MMS connections.
  issue unauthorized OPERATE commands for circuit breakers. open breakers on a live
  345kV line without a proper fault isolation sequence, and you risk equipment damage,
  arc flash, or cascading failures in the transmission network
- forge GOOSE trip signatures from any IED whose RSA key is in the SCD file. broadcast
  forged GOOSE trips across the substation multicast LAN. every subscribing IED that
  has GOOSE verification enabled will execute the trip command. coordinated forged trips
  across multiple substations is a region-scale blackout. Ukraine 2015/2016 style but
  without needing INDUSTROYER/Crashoverride malware to do the protocol work.
- many IEDs have GOOSE signature verification disabled (for the latency reasons above).
  those are already vulnerable to unauthenticated GOOSE injection. but the ones that
  have it enabled — the "secure" ones — are the target here. break RSA, break the ones
  that thought they were protected.
- MMS key compromise: the IED TLS cert is how SCADA authenticates to the IED. forge it,
  and you can send any IEC 61850 command to the IED as if you were the SCADA system.
  read protection settings, modify operating limits, enable "test mode" (which suppresses
  real trips). the IED has no other authentication mechanism once TLS cert auth is broken.

## Code

`iec62351_rsa.c` — `iec62351_mms_tls_init()` (RSA-2048 mutual TLS for IEC 61850 MMS,
`SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT`), `iec62351_sign_goose()` (RSA-2048
PKCS#1 v1.5 GOOSE trip signature per IEC 62351-5), `iec62351_verify_goose()` (signature
verification with GOOSE timing context). libIEC61850 and ABB/Siemens/SEL relay context.
