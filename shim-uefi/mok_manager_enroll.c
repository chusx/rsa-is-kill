/*
 * mok_manager_enroll.c
 *
 * MokManager / MokList handling inside shim.efi. This is the
 * code path that decides whether a GRUB / kernel / kernel module
 * may boot on a UEFI Secure Boot system when the image is NOT
 * signed by Microsoft's UEFI CA but by a distro or local key.
 *
 * Shim is signed by the Microsoft UEFI CA (the only external
 * signer Windows/Linux boxes trust out of the box). Shim then
 * maintains its own secondary trust database ("MOK" — Machine
 * Owner Key) stored in an NV-RAM boot-services variable. MOK
 * entries are RSA-2048 public keys owned by distros (Red Hat,
 * Canonical, SUSE, Debian, Oracle) or by the local sysadmin.
 *
 * An attacker who factors the Microsoft UEFI CA, the distro's
 * MOK-enrolled RSA key, or shim's own build-time allow-list
 * key owns the second-stage bootloader chain.
 */

#include <efi.h>
#include <efilib.h>
#include "shim.h"

#define MOKLIST_VAR     L"MokListRT"
#define MOKLIST_GUID    SHIM_LOCK_GUID

/* The allow-list shim was built with. In Fedora/RHEL, this is
 * the Red Hat Secure Boot key; in Ubuntu, the Canonical key;
 * in Debian, the Debian Secure Boot CA. Rotating it requires
 * re-signing shim at Microsoft and re-distributing.            */
extern const uint8_t SHIM_VENDOR_CERT[2048];
extern size_t        SHIM_VENDOR_CERT_SIZE;

struct mok_cert_entry {
    EFI_GUID type;                      /* EFI_CERT_X509_GUID   */
    UINT32   header_size;
    UINT32   size_of_signature;
    UINT32   signature_size;
    UINT8    owner_guid[16];
    UINT8    cert[];                    /* DER, RSA-2048 typ.   */
};

/* Walk MokListRT to verify a presented PE (GRUB, kernel, etc.).
 * Called from shim_verify() after Authenticode parse. */
EFI_STATUS mok_verify_binary(UINT8 *data, UINTN datasize,
                              WIN_CERTIFICATE_EFI_PKCS *cert)
{
    UINTN mok_size;
    UINT8 *mok = NULL;
    EFI_STATUS rc;

    rc = get_variable(MOKLIST_VAR, &mok, &mok_size, MOKLIST_GUID);
    if (EFI_ERROR(rc) && rc != EFI_NOT_FOUND) return rc;

    /* First try the built-in vendor cert (signed under the
     * shim-build-time distro key). */
    rc = verify_pkcs7_with_cert(cert, data, datasize,
                                SHIM_VENDOR_CERT, SHIM_VENDOR_CERT_SIZE);
    if (rc == EFI_SUCCESS) return rc;

    /* Then iterate MokListRT. Each entry is an RSA-2048 cert
     * enrolled by the machine owner via MokManager (requires
     * physical presence at the UEFI console + a password hash
     * stashed in MokAuth). */
    UINT8 *p = mok, *end = mok + mok_size;
    while (p + sizeof(struct mok_cert_entry) <= end) {
        struct mok_cert_entry *e = (void *)p;
        if (CompareGuid(&e->type, &EFI_CERT_X509_GUID) == 0) {
            rc = verify_pkcs7_with_cert(cert, data, datasize,
                                        e->cert, e->signature_size);
            if (rc == EFI_SUCCESS) return rc;
        }
        p += e->size_of_signature;
    }
    return EFI_SECURITY_VIOLATION;
}

/* =========================================================
 *  MokManager enrollment path. User-requested additions
 *  land in the "MokNew" variable from userspace
 *  (mokutil --import); at next boot, shim reads MokAuth,
 *  prompts the operator on-console for the enrollment
 *  password, and migrates MokNew into MokListRT.
 *
 *  There is no revocation except enrolling into MokListX
 *  (the dbx-equivalent) which requires the same on-console
 *  physical-presence step.
 * ========================================================= */

EFI_STATUS mok_import_new(EFI_HANDLE parent)
{
    UINTN new_size;
    UINT8 *new_data = NULL;
    EFI_STATUS rc;

    rc = get_variable(L"MokNew", &new_data, &new_size, MOKLIST_GUID);
    if (EFI_ERROR(rc)) return rc;

    /* MokAuth stores SHA256(password) chosen at `mokutil --import`
     * time. User must re-enter the password here. */
    if (!prompt_and_verify_mokauth())
        return EFI_ACCESS_DENIED;

    /* Append MokNew contents onto MokListRT. Cert format
     * unchanged from the import wire representation. */
    rc = append_mok_list(new_data, new_size);
    if (EFI_ERROR(rc)) return rc;

    /* Clear MokNew so we don't re-prompt. */
    set_variable(L"MokNew", NULL, 0, MOKLIST_GUID);
    return EFI_SUCCESS;
}

/* ---- Attack matrix on RSA break ---------------------------
 *  Microsoft UEFI CA factored (RSA-2048):
 *    Forge any shim.efi. Universal pre-OS persistence across
 *    every Windows/Linux UEFI machine on the planet. Revocation
 *    requires dbx update signed by Microsoft Production CA —
 *    which is itself RSA-2048. CRQC-resistant remediation path
 *    does not exist today; dbx updates are the only practical
 *    fleet intervention and they are rate-limited by OEM push.
 *
 *  Distro vendor-cert factored (Red Hat / Canonical / SUSE):
 *    Sign arbitrary GRUB / kernel that shim accepts as
 *    "trusted distro code". Post-boot the kernel lockdown flag
 *    is attacker-controlled -> ring 0 persistence with signed
 *    kernel modules.
 *
 *  User-enrolled MOK factored:
 *    Per-machine, but DKMS-style MOKs are often shared across
 *    large fleets (GPU drivers, VMware tools); a single key
 *    compromise is a fleet compromise.
 * --------------------------------------------------------- */
