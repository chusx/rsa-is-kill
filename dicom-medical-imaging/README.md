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

## why is this hella bad

DICOM signatures are the legal and clinical attestation that medical images are authentic. Forging them enables:

- **Alter cancer screening results**: modify CT/MRI to remove tumors from images → patient not treated → delayed diagnosis
- **Insert false findings**: add apparent masses to images → unnecessary surgery on healthy patients
- **Forge clinical trial imaging data**: DICOM signatures are used for FDA 21 CFR Part 11 compliance on clinical trials. Forged trial data → fraudulent drug/device approval → patient harm at scale
- **Radiology AI training data poisoning**: DICOM datasets with forged signatures look authentic → poison AI model training sets → compromise future AI diagnostics
- Attacks are undetectable: the forged RSA signature is mathematically valid; radiologists have no mechanism to distinguish it from an authentic signature

## Code

`dcmtk_rsa_signature_profile.cc` — `SiBaseRSAProfile::isAllowableAlgorithmType()`
returning `true` only for `EKT_RSA`, and `isAllowableMACType()` accepting
SHA-1 through SHA-512 (all with RSA). The RSA-only constraint is the DICOM
standard, not a DCMTK bug.
