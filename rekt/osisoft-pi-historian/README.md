# osisoft-pi-historian — RSA in OSIsoft/AVEVA PI industrial historian (65% of Fortune 500 industrial)

**Repository:** OSIsoft PI Server (proprietary); AVEVA PI System 
**Industry:** Industrial operations technology — utilities, oil/gas, chemical, nuclear, pharma 
**Algorithm:** RSA-2048 (PI Web API TLS cert, PI server-to-server mutual TLS, PI Connector identity certs) 

## What it does

OSIsoft PI System (now AVEVA PI) is the dominant industrial time-series historian —
it collects, stores, and serves process data from sensors, PLCs, and control systems.
Used by ~65% of Fortune 500 industrial companies: electric utilities, oil refineries,
chemical plants, nuclear power stations, pharmaceutical manufacturers.

PI Data Archive, PI AF Server, and PI Web API all use TLS with RSA-2048 certificates
for server authentication and mutual authentication between PI components. PI Connector
services (which pull data from OPC-UA servers, MQTT brokers, and control systems) authenticate
to PI Data Archive using RSA-2048 client certificates. PI-to-PI replication (plant historian
to central corporate historian) uses mutual TLS with RSA-2048 on both sides.

The PI Web API (REST interface on port 5468, IIS-hosted) presents its RSA-2048 certificate
on every TLS connection. The certificate is visible to anyone who can reach the PI server on
the OT/IT boundary network. Many PI Web API servers are accessible from corporate networks
or even the internet (they're the data interface for BI tools, dashboards, and analytics).

## Why it's stuck

- PI System server infrastructure is managed as part of OT network security, not IT.
 Certificate updates require change management and production plant coordination.
 "Update the PI historian cert" requires coordination with operations, process engineering,
 and sometimes regulatory affairs (for nuclear/pharma).
- AVEVA has not announced any non-RSA migration. PI System versioning is slow — many plants
 run PI Data Archive 2018 or 2019 and won't upgrade for years.
- PI Connector certificates are issued by the PI Certificate Authority (a Windows CA
 component of PI System). No non-RSA key type is available in the PI CA.
- For FDA-regulated pharma (21 CFR Part 11): changing the certificate scheme requires
 validation and documentation under the FDA quality system. This is a months-long process
 per deployment.

## impact

PI historian holds the operational data for industrial facilities. it's the process
intelligence layer for half of industrial civilization.

- get the RSA-2048 public key from the PI Web API TLS cert (grab it from any HTTPS
 connection to port 5468 — this interface is often accessible from corporate networks).
 factor it. now you can impersonate the PI Data Archive server to any PI client, analyst
 dashboard, or corporate BI tool pulling data from that historian.
- forge the PI data stream. power plant claiming 800MW generation? make it say 1200MW.
 refinery claiming normal operating temperatures? tell the safety monitoring system it's
 running cold. the operator console, the process analytics, the safety alerts — they all
 trust the PI server. impersonate it and you control what the operators see.
- for PI-to-PI replication: factor the source plant's RSA-2048 server cert. intercept
 the replication to the corporate historian. modify historical data as it's replicated.
 by the time anyone notices inconsistency, the audit window may have closed.
- pharmaceutical: 21 CFR Part 11 requires electronic records and signatures. PI stores
 batch records for FDA-regulated manufacturing. forging PI data signed with a valid
 RSA cert creates forged FDA audit records for drugs, biologics, or medical devices.
 product quality data for things already on the market.
- oil and gas: PI at an LNG facility monitors compressor health, separator temperatures,
 flare system operations. TRISIS targeted a safety system at an oil/gas facility.
 PI compromise isn't the same as TRISIS but it's the reconnaissance and deception layer
 that makes a targeted attack more effective — you know exactly how the process works
 and you can hide anomalies in the historian before anyone investigates.

## Code

`osisoft_pi_historian.py` — `PIServerTLSConnection.connect_with_rsa_client_cert()` (RSA-2048
mutual TLS to PI Web API), `PIServerTLSConnection.get_server_rsa_cert()` (extract server RSA-2048
cert from TLS handshake without auth), `pi_server_to_server_auth()` (PI-to-PI RSA-2048 mutual TLS
replication auth). AVEVA PI deployment scale, critical infrastructure context, FDA 21 CFR Part 11
implications in comments.
