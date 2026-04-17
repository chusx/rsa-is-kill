# iec62443-dtls-ot — RSA in IEC 62443 DTLS for industrial IoT (WirelessHART, ISA-100, OT devices)

**Repository:** OpenSSL DTLS (IEC 62443 implementations are vendor-proprietary); ISA-100.11a, WirelessHART specs 
**Industry:** Process industry ICS/OT — refinery, chemical, pharmaceutical, power, water 
**Algorithm:** RSA-2048 (IEC 62443 SL2+ device certificates; WirelessHART Network Manager cert; ISA-100.11a device auth) 

## What it does

IEC 62443 is the industrial cybersecurity standard for IACS (Industrial Automation and Control
Systems). Security Level 2+ requires device authentication via X.509 certificates. In practice,
this means RSA-2048 certificates issued by a plant PKI, verified via DTLS during device-to-gateway
communication.

This covers:
- **WirelessHART (IEC 62591)**: Process instrument wireless sensors (pressure, temperature, flow).
 Emerson Rosemount, ABB, Yokogawa field devices. DTLS with RSA-2048 for network join and
 device authentication. The WirelessHART Network Manager cert is the trust anchor for all
 devices in a mesh network.
- **ISA-100.11a**: Industrial wireless standard with similar DTLS certificate-based auth.
 Yokogawa, Honeywell field devices.
- **PROFINET with security extension** (Siemens): DTLS over industrial Ethernet for factory automation.
- **EtherNet/IP DTLS** (Rockwell Allen-Bradley): PLC and I/O module secure communications.
- **OPC-UA over UDP**: Industrial equipment protocol with embedded DTLS.

Device certificates are provisioned during plant commissioning, issued by the operator's PKI
or the device manufacturer's factory CA. The plant PKI root certificate is loaded into every
field device during installation. The device RSA-2048 certificate is available from any DTLS
handshake on the OT wireless or wired network.

## Why it's stuck

- Field device firmware update cycles are 5-10 years. Wireless HART transmitters deployed
 in 2017 run on original firmware and will for another decade. A new algorithm requires
 a firmware update to every device.
- IEC 62443-4-2:2019 was just published in 2019. Revision cycles for ISA/IEC OT security
 standards are 5-7 years. A 2025+ revision would be the earliest to include non-RSA provisions.
- OT device processors (often Cortex-M3 or M4 class) have constrained memory and compute.
 Current non-RSA algorithms (ML-KEM, ML-DSA) have larger key sizes and more CPU requirements
 than RSA-2048. Some existing devices may not have capacity to run non-RSA algorithms.
- The WirelessHART Network Manager is typically a software process on a Emerson/Honeywell
 SCADA server. Updating it requires a SCADA software update, which is a change-managed
 operation in any plant with a proper MOC (Management of Change) process.

## impact

IEC 62443 DTLS certificates authenticate industrial sensors and controllers in process
facilities. the RSA cert is how the SCADA system knows sensor data is really from the sensor.

- factor the WirelessHART Network Manager's RSA-2048 cert (available from any WirelessHART
 DTLS handshake on the wireless OT network). impersonate the Network Manager. authorize
 rogue devices to join the mesh network. inject false sensor readings into the WirelessHART
 mesh — temperature, pressure, flow readings that say everything is normal when it isn't,
 or that say there's a fault when there isn't.
- for process safety: WirelessHART pressure sensors on pipelines feed into overpressure
 protection logic. false pressure readings either trigger unnecessary shutdowns (production
 loss, potentially dangerous if mid-process) or suppress real alerts (actual overpressure
 event not detected). the RSA certificate is the only authentication for these sensors.
- for pharmaceutical: 21 CFR Part 11 requires audit trails for process parameters. WirelessHART
 sensors in pharmaceutical manufacturing feed into batch records. forging sensor authentication
 means you can inject false process data into FDA-regulated batch records.
- ISA-100.11a for oil and gas: Yokogawa wireless sensors on offshore platforms, refineries,
 LNG facilities. the same attack chain: factor device cert, impersonate device, inject false
 readings. combine with other access and you have the reconnaissance + deception layer for
 a targeted ICS attack — know what the process is doing and hide what you're doing to it.
- PROFINET security in automotive manufacturing: Siemens S7-1500 PLCs authenticating to
 field devices via PROFINET DTLS. factor the PLC RSA-2048 cert, impersonate the PLC to
 the field devices, issue unauthorized actuator commands in an automotive assembly line.

## Code

`iec62443_dtls_rsa.c` — `iec62443_dtls_server_init()` (DTLS server with RSA-2048 mutual TLS,
IEC 62443 cipher list, `SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT`),
`iec62443_dtls_device_handshake()` (ICS device DTLS connect with RSA-2048 device cert),
`wirelesshart_dtls_join()` (WirelessHART mesh join via DTLS RSA-2048). WirelessHART
Network Manager trust anchor model and ISA-100.11a deployment context in comments.
