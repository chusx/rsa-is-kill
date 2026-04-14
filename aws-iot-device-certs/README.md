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

## impact

IoT devices are everywhere and their certificates are often 10-year validity. there are a lot of HNDL-captured TLS handshakes out there sitting on disks somewhere, each one containing a device public key.

- forge an industrial sensor certificate and inject false temperature, pressure, or flow readings. automated systems respond to the phantom data. best case: spurious emergency shutdowns. other cases: less good
- smart building access panels: forge the certificate, send "door unlocked" events to the SIEM, and the physical security audit trail shows nothing suspicious because the cert verified fine
- medical IoT (glucose monitors, infusion pumps): forge the device identity and inject false readings into hospital patient monitoring. not a good time
- fleet GPS trackers: forge device certificates, falsify location data for entire logistics fleets, and break automated routing and supply chain visibility in exciting ways
## Code

`aws_iot_rsa_device_cert.c` — Example device certificate metadata (RSA-2048,
10yr validity), FreeRTOS corePKCS11 context, ESP-IDF mbedTLS setup, nRF9160
AT provisioning commands, and Matter DAC structure with ECDSA P-256 hardcoding.
