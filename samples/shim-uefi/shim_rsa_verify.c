/*
 * Source: rhboot/shim - https://github.com/rhboot/shim
 * File:   shim.c + mok.c
 * License: BSD-2-Clause
 *
 * Relevant excerpt: UEFI Secure Boot chain of trust uses RSA-2048.
 *
 * Secure Boot works as follows:
 *   UEFI firmware (RSA-2048 Microsoft key)
 *     → shim.efi  (signed by Microsoft with RSA-2048)
 *       → grubx64.efi  (signed by distro with RSA-2048 MOK)
 *         → vmlinuz  (signed by distro with RSA-2048)
 *           → kernel modules  (signed with RSA-2048)
 *
 * The UEFI spec mandates RSA-2048 for all signatures in this chain.
 * shim explicitly rejects RSA-4096 MOK keys (they cause hangs during
 * verification).  There is no PQC signing scheme in the UEFI spec.
 *
 * If RSA-2048 is broken:
 *   - Attackers forge Microsoft's Secure Boot signature → install any bootkit
 *   - The entire verified boot chain of every Linux/Windows machine collapses
 *   - Every signed kernel module, every signed EFI binary is forgeable
 *   - Secure Boot becomes worse than useless: a false sense of security
 *
 * Microsoft controls the root key.  Rotating to PQC requires:
 *   1. UEFI Forum updating the spec (multi-year process)
 *   2. Microsoft issuing new PQC root keys
 *   3. Firmware updates to ALL shipped PCs (billions of devices, many
 *      of which will never receive a firmware update)
 *   4. All distros re-signing their bootloaders with the new algorithm
 */

/*
 * shim's verify_image() entry point - the PE binary (GRUB, kernel)
 * is verified against certificates loaded from UEFI secure variables.
 * All certificates in db/dbx/MOK are RSA-2048 X.509.
 */
efi_status_t
verify_image(void *data, unsigned long datasize,
             EFI_LOADED_IMAGE *li, PE_COFF_LOADER_IMAGE_CONTEXT *context)
{
    /*
     * Check the image against the UEFI Signature Database (db).
     * db entries are EFI_CERT_X509_GUID structs containing DER-encoded
     * X.509 certificates.  All production db entries use RSA-2048.
     * The verification delegates to OpenSSL's RSA_verify() via the
     * EFI crypto library.
     */
    efi_status = check_db_cert(L"db", global_vendor, context,
                               hash, hashsize, L"Secure Boot");
    if (efi_status == EFI_SUCCESS)
        return efi_status;

    /*
     * Check against Machine Owner Keys (MOK) - user-enrolled certs.
     * shim documentation explicitly states:
     *   "Use a 2048-bit RSA key. shim will not support adding a 4096
     *    RSA key to the MokList — it might freeze when loading and
     *    verifying the grubx64.efi binary."
     *
     * This means not only is PQC unsupported, even RSA-4096 is broken.
     * The entire boot integrity guarantee depends on RSA-2048.
     */
    efi_status = check_db_cert(L"MokListRT", shim_lock_guid, context,
                               hash, hashsize, L"MOK");
    return efi_status;
}

/*
 * Certificate enrollment into MOK list.
 * EFI_CERT_TYPE_X509_GUID identifies an X.509 certificate.
 * The certificate content is always RSA-2048 DER-encoded.
 * No PQC certificate type GUID exists in the UEFI specification.
 */
EFI_STATUS
fill_esl_with_one_signature(const UINT8 *cert, const UINTN certsize,
                            EFI_GUID *type,     /* EFI_CERT_TYPE_X509_GUID */
                            EFI_GUID *owner,    /* SHIM_LOCK_GUID */
                            UINT8 *out, UINTN *outsize)
{
    EFI_SIGNATURE_LIST *sl = (EFI_SIGNATURE_LIST *)out;
    sl->SignatureType = *type;       /* X509 - must contain RSA-2048 cert */
    sl->SignatureListSize = sizeof(EFI_SIGNATURE_LIST)
                           + sizeof(EFI_SIGNATURE_DATA) - 1
                           + certsize;
    /* ... copy cert bytes ... */
}
