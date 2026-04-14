# dlms-smart-meter — ECDSA/ECDH in smart meter communication

**Standard:** IEC 62056 (DLMS/COSEM), Security Suite 1 and 2  
**Industry:** Smart grid, utility metering — electricity, gas, water  
**Algorithm:** ECDSA P-256 / ECDH P-256 (Suite 1), ECDSA P-384 / ECDH P-384 (Suite 2)  
**PQC migration plan:** None — IEC TC57 WG14 has no PQC work item; no Suite 3 with PQC defined

## What it does

DLMS/COSEM (Device Language Message Specification / Companion Specification for Energy
Metering) is the dominant protocol for smart electricity, gas, and water meters
worldwide. IEC 62056-8-3 defines the security suites:

- **Security Suite 0:** AES-128 symmetric only (no PKC, low-end meters)
- **Security Suite 1:** ECDH P-256 + ECDSA P-256 + AES-128 — most common
- **Security Suite 2:** ECDH P-384 + ECDSA P-384 + AES-256 — high-security

Suite 1 is the standard for EU smart meter rollouts (UK SMETS2, Germany BSI
mandated meters, Italy, Spain, Netherlands). Suite 2 is used in critical
infrastructure metering and high-value commercial/industrial installations.

Head-end systems (the utility's SCADA/AMI system) send authenticated commands
to meters — disconnect relay (cut power), update tariffs, change measurement
intervals, firmware updates. These commands are signed with ECDSA P-256/P-384.
The meter stores the head-end's public key at provisioning time.

## Why it's stuck

- IEC TC57 WG14 (the committee responsible for IEC 62056) has no active work
  item for a PQC security suite. There is no "Security Suite 3" defined or in progress
- Smart meters have 10-15 year deployment lifespans. UK SMETS2 meters deployed in
  2019-2025 will be in homes until 2034+
- Meter firmware can be updated OTA in many deployments (it's how tariffs are pushed),
  but the key infrastructure (head-end signing keys, meter provisioning) would need
  a coordinated utility-wide re-keying process
- The EU Smart Metering Directive mandates IEC 62056 compliance. Any PQC migration
  requires regulatory approval and updated compliance certification

## impact

head-end signing keys authorize commands to every meter in a utility deployment.
in a large utility, that's millions of meters that will execute whatever has a
valid ECDSA signature.

- factor the head-end ECDSA P-256 signing key (stored in their AMI SCADA system,
  the public key is in every meter) and forge arbitrary commands to every meter in
  the deployment. disconnect relay on millions of homes simultaneously. that's a
  grid-scale power outage from software
- forge tariff update commands that corrupt billing data across an entire city's
  meter base. every bill is wrong, and the signatures look valid, so there's no
  cryptographic way to detect the tampering after the fact
- forge firmware update commands with a malicious meter firmware. meter continues
  to report false readings while running attacker code with access to the distribution
  network's AMI infrastructure
- ECDH P-256 for key agreement: HNDL-captured meter communication sessions can be
  retroactively decrypted once the ECDLP is solved. historical consumption data,
  occupancy patterns (meters report every 15-30 minutes), infrastructure config

## Code

`dlms_cosem_rsa.c` — `dlms_key_agreement_suite1()` (ECDH P-256 session key
establishment), `dlms_sign_command()` (ECDSA P-256 head-end command signature),
and `dlmsCertificateInfo` struct with meter X.509 certificate layout.
