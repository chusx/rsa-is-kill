# medical-device-fda — RSA in FDA-cleared medical devices

**Regulation:** FDA 21 CFR Part 820 / 2023 Consolidated Appropriations Act §3305  
**Industry:** Medical devices — implants, insulin pumps, cardiac devices, ventilators  
**Algorithm:** RSA-2048 (firmware signing), RSA/ECDSA (TLS update channels)  
**PQC migration plan:** None — FDA guidance does not reference PQC; 510(k) process impedes change

## What it does

The FDA's 2023 cybersecurity guidance requires medical device manufacturers
to implement cryptographically authenticated software updates. The dominant
implementation uses RSA-2048 to sign firmware images.

Critical devices with RSA-based firmware authentication:
- **Insulin pumps / AID systems**: Tandem t:slim X2, Medtronic MiniMed 780G,
  Insulet OmniPod 5 — all receive OTA updates via Bluetooth + cloud (TLS/RSA)
- **Cardiac implantable devices** (pacemakers, ICDs): remote monitoring via
  Medtronic CareLink, Abbott Merlin.net — RSA/TLS from programmer to cloud
- **Hospital infusion pumps**: BD Alaris, Baxter Spectrum — firmware over
  hospital Wi-Fi, RSA-signed update packages
- **Diagnostic imaging**: CT/MRI/X-ray systems run Windows with Authenticode
  RSA code signing for device driver and application updates

## Why it's stuck

**Regulatory**: Changing the cryptographic algorithm in an FDA-cleared device
may require a new 510(k) submission ("substantial equivalence" review) or
De Novo authorization — adding 6-18 months and $50K-$500K per change.
Manufacturers avoid algorithm changes that trigger new clearances.

**Technical**: Implantable devices (pacemakers, ICDs) communicate over
proprietary 175 kHz or MICS-band radio with low-bandwidth programmers.
The communication protocol is frozen by regulatory clearance. Adding PQC
signatures (typically 1-3 KB for ML-DSA) to a protocol designed for
100-byte packets is not feasible without a complete redesign.

**Lifespan**: Cardiac implants have 10-15yr battery lifetimes. A pacemaker
implanted in 2024 may still be operating in 2039 with the same RSA key.

## Code

`fda_firmware_signing.c` — `medical_device_verify_firmware()` (RSA-2048
PKCS#1 v1.5 verify before flash), the `FirmwareHeader` struct with
256-byte RSA signature field, and analysis of implantable device constraints.
