# UEFI Secure Boot / shim — RSA-2048 Boot Chain

**Source:** https://github.com/rhboot/shim  
**Files:** `shim.c`, `mok.c`  
**License:** BSD-2-Clause

## what it does

`shim` is the first-stage bootloader loaded by UEFI firmware on every major Linux distribution. It is signed by Microsoft, and it in turn verifies GRUB, which verifies the kernel, which verifies kernel modules. This chain — firmware → shim → GRUB → kernel → modules — is the entire verified boot guarantee that modern systems rely on.

## impact

shim is the first thing that runs after UEFI hands off to the bootloader on most Linux systems. it's signed with a Microsoft certificate that lives in UEFI firmware across hundreds of millions of PCs.

- forge a shim binary that passes the Microsoft RSA signature check. every PC trusting the Microsoft UEFI CA will boot your shim. that's basically every PC that runs Linux with Secure Boot
- a malicious shim runs before the kernel and before any OS security mechanism. install a bootkit that survives OS reinstalls and secure wipes because it runs before any of that matters
- Microsoft's UEFI CA signs shim for Fedora, Ubuntu, Debian, RHEL, and every other major distro that uses shim. one RSA key, all of Linux secure boot
- Secure Boot is the foundation of measured boot, TPM attestation, and confidential computing root-of-trust chains. it all starts with this RSA signature
## migration status

No PQC Secure Boot spec from UEFI Forum. Microsoft has not announced a timeline. Even if they did, the firmware update deployment problem makes this a decade-long project.
