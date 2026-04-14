# dicom-medical-imaging — RSA-only in the global medical imaging standard

**Software:** DCMTK (DCMTK/dcmtk) — reference DICOM implementation  
**Industry:** Radiology, pathology, oncology — all medical imaging  
**Algorithm:** RSA (any size) — the ONLY algorithm allowed in DICOM Base RSA Digital Signature Profile  
**PQC migration plan:** None — DICOM PS 3.15 Annex G has no PQC profile; NEMA has not published plans

## What it does

DICOM is the universal format for medical imaging: CT, MRI, X-ray, ultrasound,
PET, digital pathology. Every hospital PACS, radiology workstation, and imaging
device globally speaks DICOM.

DICOM Digital Signatures (PS 3.15 Annex G) let clinicians or AI systems sign
imaging datasets to certify authenticity and integrity. The **Base RSA Digital
Signature Profile** is the only profile defined — it accepts exclusively
`EKT_RSA` (RSA keys of any size). ECDSA is not in the spec. PQC is not in
the spec.

Signed DICOM data includes:
- Diagnostic images and measurements (CT/MRI findings)
- Structured reports (radiology reports, HL7 CDA)
- Radiation dose records (RDSR)
- AI inference results (DICOM SR with algorithm provenance)

## Impact

A CRQC forging DICOM signatures could alter diagnostic images (remove a tumor,
change a measurement) without detection. The forged signature would pass
verification against the embedded RSA certificate.

FDA 21 CFR Part 11 requires authentic electronic signatures on clinical trial
data. DICOM RSA signatures are used for this purpose. Forged clinical trial
imaging data undermines drug/device regulatory approvals.

## impact

DICOM digital signatures are how you prove a medical image hasn't been tampered with. they're used for FDA 21 CFR Part 11 compliance, legal attestation, and clinical trials. the system works on the assumption that RSA is hard to forge.

- modify a CT or MRI to remove tumors before a radiologist sees it. the patient doesn't get treated, and nobody detects the tampering because the RSA signature is mathematically valid
- add apparent masses to images. unnecessary surgery on a healthy patient. again, signature verifies, nothing looks wrong to the system
- forge clinical trial imaging data. fraudulent drug or device approval, patient harm at scale, all with a passing signature check
- DICOM datasets with forged signatures look authentic and get used to train radiology AI models. you can poison the training data and compromise future AI diagnostics, quietly
## Code

`dcmtk_rsa_signature_profile.cc` — `SiBaseRSAProfile::isAllowableAlgorithmType()`
returning `true` only for `EKT_RSA`, and `isAllowableMACType()` accepting
SHA-1 through SHA-512 (all with RSA). The RSA-only constraint is the DICOM
standard, not a DCMTK bug.
