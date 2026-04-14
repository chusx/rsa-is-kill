# UEFI Secure Boot / shim — RSA-2048 Boot Chain

**Source:** https://github.com/rhboot/shim  
**Files:** `shim.c`, `mok.c`  
**License:** BSD-2-Clause

## what it does

`shim` is the first-stage bootloader loaded by UEFI firmware on every major Linux distribution. It is signed by Microsoft, and it in turn verifies GRUB, which verifies the kernel, which verifies kernel modules. This chain — firmware → shim → GRUB → kernel → modules — is the entire verified boot guarantee that modern systems rely on.

## why is this hella bad

- The UEFI specification mandates RSA-2048 for all Secure Boot signatures.
- shim explicitly rejects RSA-4096 MOK keys — they cause hangs. RSA-2048 is not just the default, it's the maximum.
- Microsoft's root Secure Boot key is RSA-2048. Forging it breaks every Windows and Linux machine with Secure Boot enabled.
- A CRQC attacker can forge shim's Microsoft signature → install any bootkit on any PC, bypass all OS-level security, before the OS even loads.
- Updating the root key requires UEFI firmware updates on billions of devices, most of which will never receive one (cheap consumer hardware, EOL systems, embedded devices).
- The `EFI_CERT_TYPE_X509_GUID` type used throughout shim has no PQC equivalent in the UEFI specification.

## migration status

No PQC Secure Boot spec from UEFI Forum. Microsoft has not announced a timeline. Even if they did, the firmware update deployment problem makes this a decade-long project.
