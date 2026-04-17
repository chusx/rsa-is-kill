# Illumina DNA sequencers — signed firmware, BaseSpace telemetry,
# reagent kit RFID authentication

Illumina sequencers dominate clinical + research genomics:
- **NovaSeq 6000 / X+ / X Plus** — large-capacity production
  sequencers at every major clinical laboratory (Mayo, Quest,
  LabCorp, ARUP), genome centers (Broad Institute, Wellcome
  Sanger, BGI), pharma R&D (Regeneron, Novartis, Pfizer).
- **NextSeq 1000/2000** — mid-market clinical + translational.
- **MiSeq / iSeq / MiniSeq** — decentralized clinical
  microbiology, pathogen ID, pharmacogenomics.

Every one of ~25,000 deployed Illumina instruments worldwide
touches RSA at:

## 1. Instrument firmware + control-software signing
Every update to SBS (sequencing-by-synthesis) run-control software
and its embedded FPGA bitstream is RSA-signed by Illumina's
release HSM. The instrument's Windows-embedded OS verifies code-
signing on every executable launched during a run.

## 2. Reagent kit RFID + cloud validation
Every reagent cartridge carries an RFID tag with a one-time lot
ID and signed expiration + lot-tracking payload. The instrument
reads the RFID, RSA-verifies the signature against the Illumina
reagent-trust root, and refuses to run if the signature is
invalid, the kit is past expiration, or if BaseSpace cloud
lookup flags the lot as recalled. This is the DRM-ish layer
underwriting Illumina's consumables business model (~85% of
Illumina revenue is reagent consumables).

## 3. BaseSpace Sequence Hub telemetry + data upload
Run metadata, BCL tile quality metrics, run completion events
are pushed to BaseSpace over TLS mutual-auth (RSA-2048 instrument
cert + Illumina CA server cert). For clinical workflows under
CAP/CLIA/ISO 15189, the signed run-result record is part of the
accredited chain of custody.

## 4. DRAGEN secondary-analysis pipeline
DRAGEN output BAMs + VCFs are often countersigned by the on-prem
DRAGEN server (RSA key in the DRAGEN field-HSM) before upload
to the LIMS. Clinical laboratories running germline + tumor-only
variant calling retain these signatures as audit evidence for
FDA-regulated NGS assays.

## 5. IVD / regulatory reporting
**FDA-cleared** + **IVDR CE-marked** Illumina workflows
(TruSight Tumor 170, MiSeqDx, NovaSeq 6000 Dx): the instrument's
run-lock is enforced by firmware whose RSA signature proves the
correct validated-for-IVD build is running. Clinical laboratories
submit signed run metadata to state health departments + CMS as
part of PAMA and QSR compliance.

## 6. Inter-institutional data sharing
**dbGaP**, **ENA**, **TCGA**, **UK Biobank**, **All of Us**
participant data flows between hospitals and repositories through
signed transfer bundles (`ENA XML manifests`, Globus signed-URL
exports) — RSA underlies the attestation that the data came
from an authorized clinical source.

## Scale

- ~$4.5B/yr Illumina revenue, ~85% reagent + services, all gated
  by the RSA-signed consumable ID
- >1 million human genomes sequenced/year on Illumina platforms
- Every major clinical NGS lab depends on firmware integrity as
  a core accreditation assumption

## Breakage

A factoring attack against:

- **Illumina firmware-signing CA**: attacker pushes a signed
  firmware that fakes QC metrics, silently drops flagged variants
  from VCF output, or exfiltrates clinical data to attacker
  endpoints. Fleet-wide trust in NGS results collapses; CAP/CLIA
  audit-reportable impact across thousands of clinical labs.
- **Illumina reagent-signing key**: attacker clones reagent RFID
  tags, sells counterfeit reagent kits to labs (the gray-market
  Illumina reagents industry already attempts this; RSA is
  currently the defense). Undocumented chemistry variability in
  clinical assays has patient-care consequences.
- **BaseSpace mutual-auth CA**: forged run-metadata uploads from
  non-existent instruments; clinical-lab operational-audit
  integrity collapses.
- **DRAGEN HSM root**: forged clinical-grade variant call records,
  with potential for fabricated evidence in forensic genomics
  (paternity, relatedness, forensic DNA casework using the same
  technology stack).

Sequencer instrument lifecycles are 7-10 years. Firmware push
is Illumina-controlled and quarterly. A factoring compromise has
a multi-quarter-to-years cleanup window during which clinical
NGS results have a cryptographic-trust asterisk.
