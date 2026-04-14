# aws-iot-device-certs — RSA/ECDSA in ~1 billion IoT devices

**Services:** AWS IoT Core, Azure IoT Hub, Google Cloud IoT, Matter/Thread  
**Hardware:** ESP32, nRF9160, STM32, i.MX RT, Nordic nRF52  
**Industry:** Smart home, industrial IoT, agriculture, asset tracking  
**Algorithm:** RSA-2048 (AWS IoT default), ECDSA P-256 (Matter/Azure IoT)  
**PQC migration plan:** None — no PQC device cert profile in any major IoT platform

## What it does

Every device connected to AWS IoT Core, Azure IoT Hub, or the Matter fabric
is authenticated by an X.509 certificate tied to a keypair stored in the
device's flash memory (or crypto chip). AWS IoT Core documentation recommends
RSA-2048 as the default. Azure DPS supports RSA and ECDSA. Matter 1.3 uses
ECDSA P-256 for the Device Attestation Credential (DAC).

All of these break under Shor's algorithm.

## Hardware specifics

| MCU | Key storage | Certificate type | Update path |
|---|---|---|---|
| ESP32 / ESP32-S3 | NVS flash partition | RSA-2048 PEM | OTA firmware re-provision |
| Nordic nRF9160 | Modem AT-command NVM | RSA-2048 PEM | AT command (requires connectivity) |
| STM32 + ATECC608 | ATECC608 secure element | ECDSA P-256 | Physical chip replacement |
| NXP i.MX RT | IEE-encrypted flash | RSA-2048 | Signed OTA |

## Why it's stuck

No major IoT cloud platform supports PQC device certificates because:
1. No X.509 profile for ML-DSA/SLH-DSA leaf certificates is standardized
2. Embedded TLS libraries (mbedTLS, wolfSSL, BearSSL) don't support PQC in
   ROM-sized builds that fit on constrained MCUs (64-256 KB flash)
3. AWS IoT Core, Azure IoT Hub, and Matter do not accept PQC certificates
4. IANA has not assigned OIDs for PQC algorithms in X.509

Even if libraries added PQC, the network effect problem remains: a device
can't use PQC until its cloud endpoint accepts it, and vice versa.

## why is this hella bad

IoT devices are embedded everywhere. Forging their identities means:

- **Industrial IoT**: forge a sensor reading device's certificate → inject false temperature/pressure/flow readings → cause automated systems to respond to phantom conditions (e.g., trigger emergency shutdowns or disable alarms)
- **Smart building**: forge access control panel certificate → send "door unlocked" events to cloud SIEM → defeat physical security audit trail
- **Medical IoT** (glucose monitors, smart infusion pumps): forge device identity → inject false readings into hospital patient monitoring systems
- **Fleet tracking**: forge vehicle GPS trackers → falsify location data for entire logistics fleets
- At IoT scale, HNDL-captured TLS handshakes contain device certificate public keys — a CRQC can batch-process millions of device identities and forge them all simultaneously

## Code

`aws_iot_rsa_device_cert.c` — Example device certificate metadata (RSA-2048,
10yr validity), FreeRTOS corePKCS11 context, ESP-IDF mbedTLS setup, nRF9160
AT provisioning commands, and Matter DAC structure with ECDSA P-256 hardcoding.
