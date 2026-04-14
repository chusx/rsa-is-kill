# arm-trustzone-tfa — RSA in the ARM Trusted Firmware boot chain

**Software:** ARM Trusted Firmware-A (ARM-software/arm-trusted-firmware)  
**Hardware:** NXP i.MX 8M/93, Rockchip RK3568/3588, STM32MP1, Marvell OCTEON TX2, MediaTek  
**Algorithm:** RSA-2048 or ECDSA-P256 ROTPK (Root-of-Trust Public Key)  
**PQC migration plan:** None — TBBR spec (ARM DEN0006) has no PQC ROTPK format; OTP fuses are immutable

## What it does

ARM TF-A is the reference secure world firmware for ARMv8-A processors. It
implements Trusted Board Boot (TBB): each stage of the boot chain
(BL1→BL2→BL31→BL32→BL33) is authenticated with a signature before execution.

The trust root is a ROTPK — typically RSA-2048 or ECDSA-P256 — whose SHA-256
hash is burned into OTP (One-Time Programmable) fuses at manufacturing. The
ROTPK itself is embedded in BL2. If the ROTPK's RSA key is broken, an attacker
can forge any firmware in the boot chain.

## Why it's stuck

- **OTP fuses are permanent**: the ROTPK hash cannot be changed after manufacturing
- **TBBR spec gap**: ARM DEN0006 defines no PQC ROTPK format or OID
- **Hardware accelerator gap**: NXP CAAM (used on i.MX) supports RSA-4096 max;
  ML-DSA is a different operation the hardware cannot perform
- **SoC lifecycle**: i.MX 8M processors in 2025 automotive head units will be
  running in 2040 with the same OTP-locked ROTPK

## why is this hella bad

TF-A runs at EL3 — the highest privilege level on ARM processors, above the hypervisor (EL2) and OS kernel (EL1). Compromising it means:

- **Forge any firmware in the BL1→BL2→BL31 chain** → execute arbitrary code in EL3 → full control of the Trusted Execution Environment (TEE), TrustZone secure world
- **Persistent hypervisor-level rootkit**: malicious BL31 survives OS reinstalls, hypervisor updates, and "secure wipe" operations — it runs before any OS gets control
- **Break OP-TEE (BL32)**: the secure world TEE runs trusted applications (DRM, mobile payments, biometric processing). A compromised TF-A can inspect or modify all TEE memory
- **NXP i.MX 8 automotive head units**: TF-A compromise → access to CAN bus routing, ECU communication proxied through the infotainment SoC
- The ROTPK hash is burned into OTP — the hardware can't tell the difference between a legitimate signed firmware and a forged one with the same RSA key

## Code

`mbedtls_crypto_verify.c` — `verify_signature()` (mbedTLS-based RSA/ECDSA
firmware auth called for every boot image) and `rsa_public_verif_sec()` (NXP
CAAM hardware RSA modular exponentiation for accelerated boot authentication).
