# uboot-secure-boot — RSA in embedded Linux bootloaders

**Software:** U-Boot (u-boot/u-boot) 
**Hardware:** Raspberry Pi, BeagleBone, NXP i.MX, TI AM335x/AM62x, Rockchip, Allwinner 
**Algorithm:** RSA-2048 or RSA-4096 (FIT image Verified Boot) 

## What it does

U-Boot is the bootloader for virtually every embedded Linux system. Verified
Boot uses RSA to authenticate the Flattened Image Tree (FIT) — kernel, device
tree, and initrd — before handing control to the OS. The RSA public key is
embedded inside U-Boot's own device tree blob at build time.

This is the foundation of the entire system trust chain. If U-Boot Verified
Boot is compromised, every layer above it (kernel, initramfs, applications)
is also untrustworthy.

## Why it's stuck

- The RSA public key is baked into U-Boot at build time
- On eFUSE-locked devices, the secure boot configuration cannot be changed
 without hardware access (and is physically prevented by design)
- Updating to non-RSA would require reflashing U-Boot with a new public key
 embedded in the FDT — but you can't authenticate the new U-Boot without
 the old RSA key, and if the old RSA key is compromised you can't trust it
- There is no non-RSA FIT image signing algorithm in U-Boot's `mkimage` tool

## Scale

Affected devices include: Raspberry Pi CM4/Pi 5, every BeagleBone variant,
NXP i.MX 6/8 (automotive head units, industrial HMIs), TI AM335x
(industrial PLCs, HMIs), Rockchip RK3588 (NAS, AI boxes), Allwinner H616
(TV boxes), and any ARM board using U-Boot Verified Boot.

## impact

U-Boot secure boot is the trust anchor for embedded Linux devices: routers, industrial gateways, automotive head units, medical devices, network appliances. the RSA key is what stands between "known good firmware" and "whatever."

- forge a firmware image that passes RSA verification in U-Boot. flash it to any device using U-Boot secure boot. persistent compromise that survives factory reset because it runs before everything else
- the ROTPK hash is burned into OTP. the hardware cannot distinguish a forged firmware from a legitimate one once you have the RSA key
- industrial devices running U-Boot are often in the field for 10-20 years. devices deployed today will still be running in 2040 with the same RSA key baked into their OTP fuses, and that key cannot be changed
- routers: forge firmware, own the network gateway. IoT gateways: forge firmware, own the device fleet management plane
## Code

`rsa_verify.c` — `rsa_verify_key()` (modular exponentiation + PKCS#1.5 verify
at boot time) and `rsa_sign()` (host-side signing in `mkimage`), with the
`rsa_public_key` struct that is embedded in U-Boot's FDT.
