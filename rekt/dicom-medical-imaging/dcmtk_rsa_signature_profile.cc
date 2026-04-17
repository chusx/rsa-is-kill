/* Source: DCMTK/dcmtk dcmsign/libsrc/sibrsapr.cc + dcmsign/apps/dcmsign.cc
 *
 * DICOM (Digital Imaging and Communications in Medicine) is the universal
 * standard for medical imaging data: CT scans, MRI, X-ray, ultrasound, PET.
 * Every hospital, radiology center, and PACS (Picture Archiving and
 * Communication System) globally uses DICOM.
 *
 * DICOM Digital Signatures (PS 3.15, Annex G) allow signing DICOM datasets
 * to ensure data integrity and authenticity. The only supported asymmetric
 * algorithm is RSA (via "Base RSA Digital Signature Profile").
 *
 * DCMTK is the reference open-source DICOM toolkit used by:
 *   - Orthanc, Horos, OsiriX, 3D Slicer, ITK, VTK
 *   - Hospital PACS systems (Sectra, Philips PACS, Agfa IMPAX)
 *   - Radiology workstations worldwide
 *
 * Patient data signed with RSA: diagnostic images, structured reports,
 * radiation dose records, genomics data. A CRQC forging DICOM signatures
 * could alter diagnostic results without detection.
 */

/* Copyright (C) 1998-2019, OFFIS e.V. — see DCMTK license */

#include "dcmtk/dcmsign/sibrsapr.h"    /* SiBaseRSAProfile */
#include "dcmtk/dcmsign/dcsignat.h"    /* DcmSignature */
#include "dcmtk/dcmdata/dcdeftag.h"

/*
 * SiBaseRSAProfile::isAllowableAlgorithmType()
 * Returns true ONLY for EKT_RSA — no ECC, no PQC.
 * This is the DICOM standard constraint: Base RSA Profile = RSA only.
 */
OFBool SiBaseRSAProfile::isAllowableAlgorithmType(E_KeyType keyType) const
{
    /* Only RSA is defined in PS 3.15 Annex G Base RSA Digital Signature Profile.
     * E_KeyType values:
     *   EKT_RSA     — RSA (any key size: 1024, 2048, 4096)
     *   EKT_DSA     — DSA (not in Base RSA Profile)
     *   EKT_EC      — ECDSA (not in Base RSA Profile)
     *   EKT_ML_DSA  — NOT DEFINED in DICOM PS 3.15
     */
    return (keyType == EKT_RSA) ? OFTrue : OFFalse;
}

/*
 * SiBaseRSAProfile::isAllowableMACType()
 * Supported MAC (hash) algorithms for DICOM RSA signatures.
 * RSA-SHA1 and RSA-MD5 are still in the spec (legacy).
 */
OFBool SiBaseRSAProfile::isAllowableMACType(E_MACType macType) const
{
    switch (macType) {
    case EMT_RIPEMD160:
    case EMT_SHA1:      /* RSA-SHA1: legacy, still in spec */
    case EMT_MD5:       /* RSA-MD5: broken, still in spec */
    case EMT_SHA256:    /* RSA-SHA256: current best practice */
    case EMT_SHA384:
    case EMT_SHA512:
        return OFTrue;
    default:
        return OFFalse;
    }
}

/*
 * dcmsign command-line tool usage (creates/verifies DICOM digital signatures):
 *
 *   dcmsign +s private_key.pem certificate.pem --sign input.dcm output.dcm
 *     → creates RSA signature in DICOM Digital Signatures Sequence (0400,0500)
 *
 *   dcmsign --verify signed.dcm
 *     → verifies RSA signature against certificate embedded in dataset
 *
 * The signing certificate (RSA-2048 or RSA-4096 X.509) is embedded directly
 * in the DICOM dataset in the Digital Signatures Sequence. This means:
 *   1. The RSA public key is stored inside every signed DICOM file
 *   2. A CRQC recovering the private key from this public key can forge
 *      signatures on any medical imaging data
 *   3. Altered diagnostic images (changed measurements, removed findings)
 *      would be indistinguishable from genuine signed data
 *
 * DICOM PS 3.15 Annex G was last updated in 2024. No PQC signature profile
 * has been added. NEMA (DICOM standard body) has not published PQC plans.
 *
 * Regulatory context: FDA 21 CFR Part 11 requires electronic signatures on
 * clinical trial data. DICOM signatures are used for this purpose.
 * Forged or undetectable alterations to clinical trial imaging data would
 * undermine the regulatory foundation of drug/device approvals.
 */

/* SiCreatorProfile (RSA with SHA-256) — used in Creator RSA Digital Signature Profile */
OFBool SiCreatorRSAProfile::isAllowableAlgorithmType(E_KeyType keyType) const
{
    return (keyType == EKT_RSA) ? OFTrue : OFFalse;  /* RSA only, same constraint */
}
