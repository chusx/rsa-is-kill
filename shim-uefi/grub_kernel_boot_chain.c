/*
 * grub_kernel_boot_chain.c
 *
 * How `shim_rsa_verify.c` is actually driven across the UEFI Secure
 * Boot chain on every signed Linux install on the planet: Fedora,
 * RHEL, Rocky, Alma, Oracle Linux, SUSE, openSUSE, Ubuntu, Debian,
 * Arch. Every single one of them boots via:
 *
 *   UEFI firmware → shim → GRUB (or systemd-boot) → vmlinuz → initrd
 *
 * with `shim` as the critical MS-UEFI-CA-signed hand-off shim. shim
 * carries the distro's own RSA-2048 CA ("Red Hat Secure Boot CA",
 * "SUSE Linux Enterprise Secure Boot CA", "Canonical Ltd. Master
 * Certificate Authority") inside its `.vendor_cert` section, and
 * exposes `EFI_SHIM_LOCK_PROTOCOL` so GRUB can call back into its
 * RSA verify path for every kernel and module it loads.
 */

#include <efi.h>
#include <efiapi.h>
#include "shim.h"

/* --- Stage 1: UEFI firmware launches shim ---
 *
 * The firmware looks up `BOOTx64.EFI` / `shimx64.efi` in the EFI
 * System Partition, walks its Authenticode PE signature, and
 * verifies against certs in the EFI `db` variable — which on every
 * OEM-shipped machine contains the Microsoft UEFI CA 2011
 * (+ 2023 rollover).  This is the RSA-2048 anchor.
 */

/* --- Stage 2: shim verifies GRUB ---
 *
 * shim re-implements the PE Authenticode verify path *inside the UEFI
 * environment* (firmware's `db` is unavailable to post-exit-boot-svcs
 * loaders), calling straight into `shim_rsa_verify.c`. The vendor
 * cert embedded at build time is the trust anchor; MOK (Machine
 * Owner Key) variables extend it at runtime for DKIM-built modules.
 */

EFI_STATUS
grub_load_and_jump(EFI_HANDLE image_handle, EFI_LOADED_IMAGE *li)
{
    EFI_STATUS rc;
    VOID *grub_image; UINTN grub_size;
    rc = read_file_from_esp(L"\\EFI\\fedora\\grubx64.efi",
                            &grub_image, &grub_size);
    if (EFI_ERROR(rc)) return rc;

    /* shim_verify() → PE parse → signature extract → RSA-2048 verify
     * under vendor_cert / MOK list / dbx deny-list.  This is the
     * primitive `shim_rsa_verify.c::verify_buffer_authenticode`. */
    rc = shim_verify(grub_image, grub_size);
    if (EFI_ERROR(rc)) return rc;   /* TPM-sealed PCR 7 remains extended */

    /* Install our SHIM_LOCK protocol so GRUB can call back ------ */
    EFI_GUID shim_lock_guid = SHIM_LOCK_GUID;
    static SHIM_LOCK shim_lock = { .Verify = shim_verify };
    EFI_HANDLE lock_handle = NULL;
    uefi_call_wrapper(BS->InstallProtocolInterface, 4,
                      &lock_handle, &shim_lock_guid,
                      EFI_NATIVE_INTERFACE, &shim_lock);

    /* Measure into TPM PCR 8 per TCG PC Client spec. */
    tpm_extend_pcr(8, sha256(grub_image, grub_size));

    /* Hand-off: LoadImage the verified GRUB and StartImage. */
    EFI_HANDLE grub_handle;
    uefi_call_wrapper(BS->LoadImage, 6, FALSE, image_handle,
                      NULL, grub_image, grub_size, &grub_handle);
    return uefi_call_wrapper(BS->StartImage, 3, grub_handle, NULL, NULL);
}

/* --- Stage 3: GRUB verifies vmlinuz + initrd ---
 *
 * GRUB's `linuxefi` (or post-2021 `linux` on unified-image distros)
 * locates shim's `EFI_SHIM_LOCK_PROTOCOL` and calls `Verify` on every
 * kernel + initramfs it loads.  That callback round-trips back into
 * `shim_rsa_verify.c`.
 */

EFI_STATUS
grub_cmd_linux(CHAR16 *kernel_path)
{
    VOID *kimg; UINTN ksz;
    read_file_from_esp(kernel_path, &kimg, &ksz);

    SHIM_LOCK *sl;
    EFI_GUID g = SHIM_LOCK_GUID;
    uefi_call_wrapper(BS->LocateProtocol, 3, &g, NULL, (VOID**)&sl);
    if (EFI_ERROR(sl->Verify(kimg, ksz))) {
        /* MOK-enrollment UI if the user wants to trust this kernel; */
        /* otherwise hard-fail and drop to rescue.                   */
        return EFI_SECURITY_VIOLATION;
    }

    tpm_extend_pcr(9, sha256(kimg, ksz));
    return linux_start(kimg, ksz);
}

/* --- Stage 4: kernel-module signing (continues post-boot) ---
 *
 * Once the kernel is running, CONFIG_MODULE_SIG_FORCE=y is the
 * default on Fedora / RHEL / SUSE / Ubuntu signed-kernel builds.
 * Every `insmod`/`modprobe` walks the appended PKCS#7 signature at
 * the tail of the .ko and verifies it against keys in the
 * .builtin_trusted_keys keyring — which on boot is seeded from
 * shim's MOK list that we built into the trust anchor back in
 * Stage 2.  That verify path is RSA-SHA256 in the kernel's
 * crypto/rsa-pkcs1pad.c, the in-kernel mirror of shim's primitive.
 */


/* ---- Breakage --------------------------------------------------
 *
 * A factoring attack against:
 *
 *   - The Microsoft UEFI CA 2011/2023 key: attacker signs an
 *     arbitrary PE that every OEM-shipped motherboard's firmware
 *     accepts as a bootloader. No kernel patch, no shim update, no
 *     dbx revocation removes this until every BIOS on earth is
 *     reflashed — multi-year supply-chain rollout (see the dbx
 *     updates for BootHole, BlackLotus for a taste of the tail).
 *
 *   - A distro vendor_cert (Red Hat / Canonical / SUSE): attacker
 *     signs a kernel+initrd combo that shim happily hands control
 *     to; bootkit achieves pre-kernel persistence across every
 *     install of that distro worldwide. TPM measurements
 *     differ, so Bitlocker / LUKS-tpm2 unseal breaks — which is the
 *     only signal an attentive operator sees, and it is easy to
 *     paper over.
 *
 *   - A MOK enrolled for out-of-tree drivers (NVIDIA, VMware,
 *     VirtualBox, ZFS, Oracle Ksplice): targeted attack against
 *     machines running those modules, including the bulk of
 *     ML/AI training hosts running NVIDIA kmod-nvidia.
 */
