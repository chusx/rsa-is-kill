# android-avb — RSA-4096 Android Verified Boot 2.0

**Software:** AOSP libavb (Android Open Source Project) 
**Industry:** Mobile devices — Android smartphones, tablets, TV boxes, automotive 
**Algorithm:** RSA-4096 (SHA-256 or SHA-512) — default OEM signing key type 

## What it does

Android Verified Boot 2.0 (AVB2) verifies every boot image (boot.img, system.img,
vendor.img, dtbo.img) before the kernel is allowed to run. The OEM signing key is
burned into the device's bootloader or stored in a write-once fuse region.

The vbmeta structure at the front of the boot partition contains:
- An RSA-4096 signature over all partition hashes
- The OEM's RSA-4096 public key (embedded in the vbmeta auxiliary block)
- Descriptor chains for each partition's hash tree

`AVB_ALGORITHM_TYPE_SHA256_RSA4096` is the typical OEM configuration.
Google Pixel devices use RSA-4096 for the vbmeta signing key.

The bootloader (usually U-Boot or LK) calls `avb_vbmeta_image_verify()` which
invokes the Montgomery modular exponentiation in `avb_rsa.c`. If verification
passes, the kernel boots. If not, the device enters fastboot or recovery.

## Why it's stuck

- The AVB2 algorithm type is a fixed 4-bit field in the vbmeta header. Adding a non-RSA
 algorithm type requires a format version bump and bootloader updates across all OEM devices
- OEM signing keys are generated at device bring-up and cannot be rotated without a
 factory re-provisioning process (some OEMs use an offline key ceremony)
- non-RSA signature sizes (ML-DSA: 2420-4595 bytes) are much larger than RSA-4096 (512 bytes).
 Bootloader memory budgets for vbmeta parsing are tight, especially on low-end devices
- The vbmeta structure is written to the first 4 KB of the vbmeta partition. ML-DSA-87
 signature alone (4595 bytes) doesn't fit in the current partition layout
- Android's CDD (Compatibility Definition Document) doesn't require non-RSA for AVB

## impact

AVB2 is what stands between "Android runs OEM-signed code" and "Android runs whatever."
OEM signing keys for major manufacturers are distributed in their factory images, which
are publicly available as OTA packages. the RSA-4096 public key has been out there since
device launch.

- factor the OEM RSA-4096 signing key (public in every distributed OTA package),
 sign arbitrary boot images with it, the device boots them without warning. no
 unlocked bootloader warning, no orange state, everything looks green
- this works on locked devices. AVB2 is the entire security guarantee that a locked
 bootloader provides. it's gone
- forge a malicious system.img or vendor.img that passes AVB2 verification. persistent
 device compromise that survives factory reset because it runs at verified boot time
 before Android even starts
- one compromised OEM RSA-4096 key affects every device of that manufacturer that uses
 the same key for vbmeta signing. could be tens or hundreds of millions of devices

## Code

`avb_rsa_verify.c` — `avb_rsa_verify()` (Montgomery modular exponentiation on RSA-4096
signature), `avb_vbmeta_image_verify()` (entry point from bootloader), and the
`AvbRSAPublicKeyHeader` layout showing the `key_num_bits` field (4096 for typical OEM keys).
