# Oil & gas pipeline SCADA — signed RTU firmware, API 1164 /
# IEC 62443 control-system cybersecurity, leak-detection integrity

US oil and natural-gas pipeline infrastructure: **~3.3 million miles
of pipelines** regulated by PHMSA (DoT) for hazardous-liquid +
natural-gas transport. Operators: Enbridge, TC Energy (TransCanada),
Kinder Morgan, Williams, Energy Transfer, Enterprise Products,
Plains All-American, Colonial Pipeline (post-2021 ransomware),
Saudi Aramco, Transneft, Gazprom, ADNOC.

Control plane: pipeline SCADA over WAN + leased-line + cellular
backup to hundreds / thousands of Remote Terminal Units (RTUs) and
Programmable Logic Controllers at compressor stations, pump
stations, mainline block valves, metering skids. Protocols: DNP3
Secure Authentication v5, Modbus TCP, IEC 60870-5-104, OPC UA.

Regulatory: **TSA Security Directive Pipeline 2021-02** (post-
Colonial) mandates cybersecurity controls; **API 1164** (Pipeline
SCADA Security, 3rd ed 2021 aligns with NIST SP 800-82, IEC 62443);
PHMSA 49 CFR Part 195 (liquids) + 192 (gas).

## RSA usage

### 1. RTU / PLC / flow-computer firmware signing
Emerson ROC800 / FB3000 / Bristol ControlWave, Schneider SCADAPack,
Siemens SIMATIC ET 200SP, ABB RTU560, GE MDS orbit + iNET, Honeywell
Experion SCADA controllers — all ship RSA-signed firmware images.
Post-2021 TSA-SD compliance has pushed operators to verify signatures
during field upgrades; legacy fleet has weaker chain but is being
rotated.

### 2. DNP3 Secure Authentication v5 update keys
DNP3-SAv5 uses pre-shared HMAC keys for per-message auth but the
**Update Key Change** command is protected by an RSA-based asymmetric
wrap (per IEEE 1815-2012). Master-to-outstation Update Keys rotate
yearly; the RSA chain binds each outstation's key to the Master
Station's identity.

### 3. OPC UA cert enrollment (control-room ↔ RTU)
Control Room servers (OSIsoft PI, AVEVA PI System, GE iFIX, AVEVA
System Platform) speak OPC UA to gateway RTUs. Per-device
certificates enrolled through plant GDS.

### 4. Leak-detection-system (LDS) integrity
Computational-pipeline-monitoring (CPM) under API 1130 requires
real-time hydraulic modelling; packet-data integrity from the flow
computers feeding the LDS is mandated. Krohne Pipepatrol, Atmos
Wave, EnergySolutions LeakNet — all take signed packet streams.

### 5. Custody-transfer measurement signing
Metering stations at pipeline interconnects are fiscal-transfer
points (billions of $/day across major interconnects). Flow-
computer event logs (Emerson ROC, ABB TotalFlow, Fisher ROC809) are
signed for custody-transfer auditability under API 21.1 / AGA-3,
AGA-7. A signed log is the evidentiary record in contract disputes.

### 6. SSO / jump-host access to the DCN
Operator SSO to the pipeline Data Communications Network uses
federated SAML (RSA-SHA256). Physical access to compressor stations
uses HID OSDP readers (cross-ref `hid-osdp-seos/`).

## Scale

- 3.3M miles US pipelines; ~1M miles international for major IOCs
- ~70% of US liquid hydrocarbons move by pipeline
- Colonial Pipeline (5,500 miles, 100M gal/day) is one operator of
  ~100 major operators
- Gas transmission daily throughput: ~80 Bcf/day in US alone

## Breakage

A factoring attack against:

- **Emerson / Schneider / Siemens RTU firmware root**: signed
  firmware deployed to compressor-station controllers that
  trips stations offline (gas supply disruption to downstream
  LDCs — heating-season mass outage) or drives pumps past pipe
  MAOP (Maximum Allowable Operating Pressure) → rupture.
- **DNP3-SAv5 Update Key chain**: attacker rotates themselves
  in as the legitimate Master, commands block valves closed or
  pressures to dangerous setpoints. Refer to the Natanz / TRITON
  style impact: engineer-operable control directly.
- **LDS packet integrity root**: attacker suppresses leak
  alarms — a spill continues undetected for hours. Deepwater
  Horizon-scale environmental liability in the wrong terrain.
- **Custody-transfer signing root**: fraud on fiscal-metering
  events worth $10M+/day at a single major interconnect.
- **SSO / jump-host federation root**: lateral movement into
  the control network. Colonial Pipeline 2021 was achieved via
  a single compromised VPN password; a signed-SAML-assertion
  path would remove the access-control barrier entirely.

Pipeline-SCADA equipment lifecycle: 20–40 years. Replacement of
a compromised firmware root touches tens of thousands of RTUs
distributed across millions of miles of pipeline, with many units
accessible only by truck, helicopter, or boat.
