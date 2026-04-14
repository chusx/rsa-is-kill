# atecc608-microchip — ECDSA burned into IoT silicon

**Hardware:** Microchip ATECC608A/B (dedicated crypto microcontroller, SOIC-8)  
**Industry:** IoT device authentication, USB-C PD, Qi wireless charging, AWS/Azure IoT  
**Algorithm:** ECDSA P-256 (hardwired in silicon — no other algorithm possible)  
**PQC migration plan:** None — fixed-function ASIC, no firmware update mechanism

## What it is

The ATECC608 is a 3mm × 2mm crypto chip that implements ECDSA P-256 in hardware.
It is soldered onto billions of IoT PCBs. The private key is generated in
hardware and never exported — but the public key is. A CRQC recovers the
private key from the public key alone.

Deployment contexts:
- **AWS IoT Greengrass**: ATECC608 holds the device X.509 private key for
  mutual TLS to AWS IoT Core
- **USB-C Power Delivery Authentication** (USB IF Auth Spec 1.0): every
  Thunderbolt dock, certified charger, and cable uses ECDSA P-256 via ATECC608
- **Qi 1.3 wireless charging**: phone/pad authentication IC
- **Google Nest / Ring**: home device attestation
- **Smart locks, thermostats**: cloud authentication

## Why it's stuck

The ATECC608 is a fixed-function ASIC. The cryptographic accelerator is
hardwired to ECDSA P-256 at the transistor level. There is:
- No firmware slot or update mechanism
- No algorithm selection register
- No way to add ML-DSA without replacing the physical chip

USB-C PD authentication (used in every certified USB4/Thunderbolt device)
hardcodes ECDSA P-256 in the USB PD 3.1 specification. Changing it requires
a new USB spec revision and hardware redesign across the entire USB ecosystem.

## impact

the ATECC608 is the identity chip in a huge fraction of deployed IoT devices. the private key never leaves the chip in hardware, which sounds great until you remember that Shor's algorithm works from the public key and never needs to touch the chip at all.

- forge any device certificate and impersonate it to AWS IoT Core, Azure IoT Hub, or GCP IoT. inject fake sensor readings, fake safety alerts, fake telemetry into industrial and medical monitoring systems
- USB-C PD authentication uses these chips to certify chargers and cables. forge a certificate for an uncertified charger and it passes in enterprise or medical environments that restrict accessories
- at IoT scale, device public keys are published in their certificates. a CRQC can batch-process millions of them and forge every single device identity without touching a single piece of hardware. billions of chips, one algorithm, one problem
## Code

`calib_sign_ecdsa.c` — `calib_sign_base()` (I2C opcode to chip, 64-byte R||S
output), `calib_sign()` (public API), and `calib_genkey_base()` (keypair
generation — public key is the input to a CRQC attack).
