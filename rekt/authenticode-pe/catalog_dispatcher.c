/*
 * catalog_dispatcher.c
 *
 * Windows code-integrity / driver-load Authenticode dispatcher.
 * This is the kernel-side path that, under Kernel Code Integrity
 * (CI) and Hypervisor-enforced Code Integrity (HVCI), decides
 * whether a driver or user-mode binary is permitted to execute.
 *
 * The check walks two parallel trust paths:
 *   1. Embedded Authenticode signature in the PE (wintrust.dll
 *      WinVerifyTrust path).
 *   2. Catalog file (.cat) lookup: if the PE's hash appears in
 *      any .cat file under %SystemRoot%\System32\CatRoot, that
 *      catalog's signer counts as having signed the PE.
 *
 * Both paths end at the Microsoft Code Verification Root
 * (RSA-2048, fused into ci.dll's trust list at build time) or
 * at an EV code-signing cert chain anchored to the same root.
 */

#include <ntddk.h>
#include "ci.h"

/* Microsoft Code Verification Root and cross-sign intermediates
 * ship in ci.dll's embedded trust list. These are not rotatable
 * without a Windows Update that ships a new ci.dll — which
 * itself must be Authenticode-signed. Circular dependency on
 * the same RSA primitive. */
extern const UINT8 MS_CODE_VERIF_ROOT[];
extern const UINT8 MS_WHQL_INTERMEDIATE[];

/* =========================================================
 *  Catalog (.cat) is a PKCS#7 SignedData where the
 *  contentInfo is a CTL (Certificate Trust List) whose
 *  subjects are member hashes. Checking a PE against a
 *  catalog = SHA hash lookup + PKCS#7 signer validation.
 * ========================================================= */

typedef struct _CATALOG_MEMBER {
    UINT8   hash[32];           /* SHA256 of the member        */
    UINT8   hash_alg;           /* 1 = SHA1, 2 = SHA256        */
    WCHAR   tag[64];            /* OS component tag            */
} CATALOG_MEMBER;

typedef struct _CATALOG_FILE {
    UINT8   pkcs7_signer_cert[2048];
    UINT32  pkcs7_signer_cert_len;
    UINT8   rsa_signature[256];
    UINT32  member_count;
    CATALOG_MEMBER members[];
} CATALOG_FILE;

NTSTATUS CiValidateImageData(PVOID ImageBase, SIZE_T ImageSize,
                              PCUNICODE_STRING ImageName,
                              BOOLEAN KernelMode)
{
    NTSTATUS st;
    UINT8 image_hash[32];
    CiHashAuthenticodePE(ImageBase, ImageSize, image_hash, 32);

    /* ---- Path 1: embedded signature ---- */
    st = CiVerifyEmbeddedSignature(ImageBase, ImageSize,
                                    MS_CODE_VERIF_ROOT);
    if (NT_SUCCESS(st)) {
        if (KernelMode &&
            !CiSignerHasKmciEku(ImageBase, ImageSize))
            return STATUS_INVALID_IMAGE_HASH;  /* KMCI requires
                                                  WHQL EKU */
        return st;
    }

    /* ---- Path 2: walk catalog store ---- */
    HANDLE catroot = CiOpenCatRoot();
    CATALOG_FILE *cat;
    while ((cat = CiNextCatalog(catroot)) != NULL) {
        /* Is image_hash a member? */
        if (!CatalogHasMember(cat, image_hash, 32))
            continue;
        /* Validate the catalog's own RSA signature under the
         * Microsoft Code Verification Root. */
        st = CiVerifyPkcs7Signature(
                cat->pkcs7_signer_cert, cat->pkcs7_signer_cert_len,
                cat->members,
                sizeof(CATALOG_MEMBER) * cat->member_count,
                cat->rsa_signature, 256,
                MS_CODE_VERIF_ROOT);
        if (NT_SUCCESS(st)) {
            if (KernelMode &&
                !CatalogSignerHasWhql(cat))
                return STATUS_INVALID_IMAGE_HASH;
            return st;
        }
    }
    return STATUS_INVALID_IMAGE_HASH;
}

/* =========================================================
 *  Driver load entry. Called from IoLoadDriver when a new
 *  DriverEntry is about to run — the last crypto check
 *  before attacker code would execute in ring 0.
 * ========================================================= */
NTSTATUS SeValidateDriverSignature(PDRIVER_OBJECT drv,
                                    PCUNICODE_STRING path,
                                    PVOID image, SIZE_T size)
{
    NTSTATUS st = CiValidateImageData(image, size, path, TRUE);
    if (!NT_SUCCESS(st)) return st;

    /* HVCI additionally checks that the image is in the
     * HVCI-allowed policy (signed WDAC policy). WDAC policy
     * files are themselves Authenticode-signed. */
    if (HvciIsEnabled()) {
        st = CiCheckWdacPolicy(image, size);
        if (!NT_SUCCESS(st)) return st;
    }

    /* Record into the Code Integrity event log for DCR/DefATP
     * ingestion. Forensic artifact only; detection is downstream
     * and depends on the signature being genuine. */
    CiAuditSuccess(path, image, size);
    return STATUS_SUCCESS;
}

/* ---- Adversary posture once MS Code Verif Root is factored
 *
 *  - Forge Authenticode sig on any driver. KMCI + HVCI accept.
 *    Kernel persistence across the entire Windows installed
 *    base; no WDAC policy saves you because WDAC policies are
 *    themselves validated by the same primitive.
 *  - Forge catalog (.cat) files — more subtle than driver sig
 *    because a single catalog can "sign" thousands of existing
 *    PEs retroactively. CI treats them as first-class trust.
 *  - dbx / Windows Update delivery of a revocation depends on
 *    an Authenticode-signed update package — the same broken
 *    primitive delivers the fix.
 *  - Recovery: Microsoft ships ci.dll with SymCrypt ML-DSA
 *    anchors AND a new Code Verification Root fused into the
 *    next ci.dll build AND a way to carry forward trust for
 *    legacy drivers. Multi-year program; interim posture is
 *    aggressive WDAC policy + ELAM + Defender heuristics.
 * --------------------------------------------------------- */
