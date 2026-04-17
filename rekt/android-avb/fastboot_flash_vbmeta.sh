#!/usr/bin/env bash
# fastboot_flash_vbmeta.sh
#
# Android Verified Boot 2.0 (AVB) — manufacturing-line flash + the
# subsequent boot-time verification flow. The OEM's signing keypair
# (RSA-4096 per AOSP avbtool defaults) lives on an HSM; this script
# runs on factory provisioning PCs and later is what attackers targeting
# bootloader unlocks / custom ROM distribution mimic.
#
# Signing logic is in `avb_verify.c`; this is the flash-time caller
# and the bootloader's cross-reference point.

set -euo pipefail

DEVICE_SERIAL="${1:?device serial required}"
BUILD_DIR="${2:?build output required}"
OEM_AVB_KEY_AVBPUBKEY="$BUILD_DIR/avb_pkmd.bin"
OEM_SIGNER_URL="https://signer.oem.internal/v1/avb-sign"

# 1. Sign partitions with the OEM HSM. avbtool's sign-related commands
#    end up calling into an HSM via PKCS#11 (see pkcs11-softhsm/).
for part in vbmeta vbmeta_system system system_ext product vendor boot init_boot; do
    avbtool add_hash_footer \
        --partition_name "$part" \
        --partition_size "$(stat -c%s "$BUILD_DIR/$part.img")" \
        --image "$BUILD_DIR/$part.img" \
        --algorithm SHA256_RSA4096 \
        --signing_helper_with_files "$OEM_SIGNER_URL" \
        --key_id "avb-release-2026" \
        --rollback_index "$(date +%Y%m%d)"
done

avbtool make_vbmeta_image \
    --output "$BUILD_DIR/vbmeta.img" \
    --algorithm SHA256_RSA4096 \
    --signing_helper_with_files "$OEM_SIGNER_URL" \
    --key_id avb-release-2026 \
    --include_descriptors_from_image "$BUILD_DIR/boot.img" \
    --include_descriptors_from_image "$BUILD_DIR/system.img" \
    --include_descriptors_from_image "$BUILD_DIR/vendor.img" \
    --chain_partition vbmeta_system:1:"$BUILD_DIR/avb_pkmd_system.bin" \
    --chain_partition vbmeta_vendor:2:"$BUILD_DIR/avb_pkmd_vendor.bin"

# 2. Factory flash via fastboot. The bootloader rejects any
#    vbmeta.img not signed by the fused OEM root RSA key (stored in
#    the device's anti-rollback region).
fastboot -s "$DEVICE_SERIAL" flash vbmeta      "$BUILD_DIR/vbmeta.img"
fastboot -s "$DEVICE_SERIAL" flash vbmeta_system "$BUILD_DIR/vbmeta_system.img"
fastboot -s "$DEVICE_SERIAL" flash boot        "$BUILD_DIR/boot.img"
fastboot -s "$DEVICE_SERIAL" flash init_boot   "$BUILD_DIR/init_boot.img"
fastboot -s "$DEVICE_SERIAL" flash system      "$BUILD_DIR/system.img"
fastboot -s "$DEVICE_SERIAL" flash vendor      "$BUILD_DIR/vendor.img"
fastboot -s "$DEVICE_SERIAL" flash product     "$BUILD_DIR/product.img"
fastboot -s "$DEVICE_SERIAL" flash system_ext  "$BUILD_DIR/system_ext.img"

# 3. Lock the bootloader — from here on, only OEM-RSA-signed vbmeta
#    will boot. `fastboot oem lock` triggers the device to also
#    validate the rollback index against the monotonically-stored
#    value in RPMB.
fastboot -s "$DEVICE_SERIAL" oem lock

# 4. QA boot + attestation check (device speaks Android Key Attestation
#    over USB debug socket, returning an X.509 cert chain that terminates
#    in Google's RSA Attestation Root — the verifier in /sdk/auth).
adb -s "$DEVICE_SERIAL" shell /system/bin/keystore_attestation_tool \
    --challenge "$(openssl rand -hex 32)" \
    --expected_rollback_index "$(date +%Y%m%d)"
