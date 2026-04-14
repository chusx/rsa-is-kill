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

## Code

`calib_sign_ecdsa.c` — `calib_sign_base()` (I2C opcode to chip, 64-byte R||S
output), `calib_sign()` (public API), and `calib_genkey_base()` (keypair
generation — public key is the input to a CRQC attack).
