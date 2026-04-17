# siemens-s7-tia — RSA in S7comm-plus PLC session auth (the post-Stuxnet "fix")

**Repository:** Siemens TIA Portal / S7comm-plus protocol (proprietary); wireshark S7comm dissector 
**Industry:** Industrial control systems — chemical plants, automotive, power, nuclear, military 
**Algorithm:** RSA-2048 (PLC device certificate, TIA Portal project signing) 

## What it does

S7comm-plus is the encrypted protocol Siemens introduced with S7-1200/1500 PLCs to replace
the old unencrypted S7comm. The PLC has an RSA-2048 device certificate (signed by Siemens'
private Device CA) baked in at the factory. When TIA Portal connects over TCP/102, the PLC
presents this certificate, TIA Portal encrypts a session key under the PLC's RSA public key,
and then AES-128 protects the rest of the connection.

TIA Portal project files (.ap17/.ap18) — which contain the PLC ladder logic programs — are
also signed with an RSA-2048 project certificate. The PLC checks this signature before
accepting a program download. This was the specific mechanism Stuxnet had to work around
by using stolen Authenticode code signing certificates to get its driver loaded.

Deployed in:
- BASF, Bayer, SABIC — chemical plant DCS
- Volkswagen, BMW — automotive body shop and assembly
- Deutsche Bahn — infrastructure and signaling
- Thyssen Krupp — blast furnace control
- Hundreds of nuclear power plants (in scope for IEC 62645)
- Water treatment, wastewater, and gas pipeline SCADA

The PLC device certificate public key is transmitted in plaintext during every
S7comm-plus TCP session setup on port 102 — visible to anyone on the OT network.

## Why it's stuck

- S7comm-plus is a closed, proprietary Siemens protocol. There is no public spec,
 no working group, no RFC process. Siemens decides when and if non-RSA gets added.
- The PLC firmware update cycle is measured in years. S7-1200/1500 firmware updates
 require Siemens service contracts, change management procedures, and often production
 shutdowns. Chemical plants and nuclear facilities do not casually update firmware.
- The device certificate is burned in at commissioning. Rotating it requires a full
 recommissioning procedure which for an ICS environment means a maintenance window
 that many operators schedule annually at best.
- Siemens has published no non-RSA roadmap for SIMATIC. The TIA Portal 2024 release notes
 mention nothing about an RSA replacement.

## impact

this is the post-Stuxnet security fix. RSA was the answer to "how do we stop the next
Stuxnet from loading arbitrary PLC programs." so if RSA breaks, the answer to that
question becomes "you can't."

- factor the S7-1500's RSA-2048 device cert (grab it from any port 102 connection on
 the OT network). impersonate the PLC to TIA Portal. feed the engineering workstation
 fake process values. the SCADA operator sees normal readings while the plant is
 doing whatever you told it to do
- decrypt recorded S7comm-plus sessions. the AES session keys were encrypted with the
 PLC's RSA key. now you have the AES keys. now you have every ladder logic program
 that was ever downloaded to that PLC and every process variable value that was ever
 read back. figure out exactly how the process works, then break it precisely
- forge TIA Portal project signatures. load arbitrary ladder logic onto the PLC.
 this is the Stuxnet attack, minus the stolen certs, minus the four zero-days,
 just math
- for chemical plants: modify reactor temperature setpoints, valve control logic, safety
 interlock programs. the SIS (safety instrumented system) is usually a separate
 network but the DCS is not. Texas City refinery explosion had 15 fatalities with
 no malicious actor involved. add a malicious actor.
- for nuclear plants: Natanz was S7-315 (no auth, Stuxnet needed zero-days). modern
 facilities with S7-1500 use S7comm-plus RSA. same outcome, different cryptographic
 prerequisite. the IEC 62645 scope includes "protection against unauthorized modification
 of I&C software" — that protection is the RSA signature

## Code

`siemens_s7_rsa.c` — `s7commp_session_init()` (S7comm-plus TLV parsing, PLC RSA-2048
cert extraction from attribute 0x09EF), `s7commp_encrypt_session_key()` (RSA-OAEP
session key encryption with PLC public key), `tia_verify_project_signature()`
(RSA-SHA256 PKCS#1 v1.5 project cert verification). Based on Klick/Rademacher et al.
S7comm-plus protocol analysis and Wireshark S7comm dissector.
