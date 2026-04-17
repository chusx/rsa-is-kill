# Clinical / research mass spec, LC, qPCR — signed instrument
# firmware, 21 CFR Part 11 audit-trail signing, LIS integration

Analytical instruments that anchor modern pharma QC, clinical
diagnostics, food safety, environmental monitoring, and forensic
toxicology:

- **Mass spectrometers**: Thermo Fisher Orbitrap / TSQ, SCIEX
  Triple Quad, Waters Xevo / SYNAPT, Agilent 6400/6500 QQQ,
  Bruker timsTOF
- **Liquid/gas chromatography**: Agilent 1260/1290 Infinity, Waters
  Acquity, Thermo Vanquish, Shimadzu Nexera
- **Real-time PCR**: Thermo QuantStudio, Bio-Rad CFX, Roche
  LightCycler
- **Genetic analysers (Sanger)**: Thermo 3500/3730xl
- **Clinical chemistry / immunoassay**: Roche cobas, Abbott
  Architect / Alinity, Siemens Atellica, Beckman AU/DxI

Install base: >1M analytical instruments globally in regulated
labs; every CLIA / CAP / ISO 15189 / ISO 17025 / GLP lab runs
multiple.

## RSA usage

### 1. Instrument firmware + embedded PC software signing
Every instrument above ships firmware and instrument-control PC
software (Xcalibur, Chromeleon, Analyst, MassHunter, Empower,
Compass, LabSolutions) with RSA code signing enforced by the
instrument bootloader and by the Windows-embedded host PC.

### 2. Method / acquisition-file signing
In regulated (21 CFR Part 11, EU Annex 11, PIC/S) workflows, method
files — the instrument-parameter document that defines a clinical
or forensic assay — are signed on approval in the Chromatography
Data System (CDS) or LIMS. Signature binds the assay's configuration
to the analyst's authority to release.

### 3. Electronic-record audit-trail signing
Empower, Chromeleon, SampleManager, LabWare, STARLIMS, LabVantage —
every data-system write is signed into an audit trail. 21 CFR Part
11 §11.70 requires electronic signatures to be "linked to their
respective electronic records to ensure that the signatures cannot
be excised, copied, or otherwise transferred to falsify an
electronic record by ordinary means." Most implementations use
RSA PKCS#7 / CMS SignedData.

### 4. LIS / LIMS mutual-TLS integration
HL7 v2.x and FHIR bridges between instruments (or their middleware,
Data Innovations Instrument Manager) and the Laboratory Information
System. Mutual TLS with RSA-2048 client certs.

### 5. Pharma / clinical cloud data-ingest
Thermo Connect, Agilent CrossLab, Waters waters_connect, SCIEX OS
cloud, Illumina BaseSpace (cross-ref `illumina-sequencer/`) — per-
instrument RSA leaf certs, signed data exports.

### 6. FDA eCTD submission signing
Drug submission dossiers (INDs, NDAs, BLAs, PMAs) aggregate assay
data; the eCTD package is digitally-signed (ICH M8). RSA is the
dominant choice today. FDA's ESG (Electronic Submissions Gateway)
verifies.

## Regulatory anchors

- **21 CFR Part 11** (US FDA electronic records / signatures)
- **EU Annex 11** + **EudraLex Volume 4 Annex 15** (validation)
- **ICH Q7 / Q9 / Q10** (pharma quality)
- **ISO 15189** (medical labs), **ISO 17025** (general)
- **OECD GLP** (preclinical)
- **SWGDRUG + SOFT** (forensic toxicology)

## Scale

- >1M regulated analytical instruments
- ~100k clinical-diagnostic LC-MS / MS running every day worldwide
- Pharma QC release: every batch of every pharmaceutical sold
  globally touches a mass spec somewhere in its release chain
- Forensic tox (post-mortem, DUI, doping): RSA-signed chromatograms
  are the evidentiary record

## Breakage

A factoring attack against:

- **An instrument-vendor firmware-signing root**: signed firmware
  that subtly biases m/z calibration, retention-time calibration,
  or ion-ratio reporting. Clinical false-positives or -negatives
  on drug-level assays (therapeutic drug monitoring, tox screens),
  food-contaminant testing, pharma impurity profiling.
- **A CDS audit-trail signing key**: 21 CFR Part 11 compliance
  collapses for every regulated lab using that platform.
  Electronic records legally invalid; product releases pending
  data must be repeated or re-verified by paper. FDA 483 / Warning
  Letter exposure for every site.
- **A method-file signing root**: signed forgeries of validated
  clinical/forensic assays; false lab results used in criminal
  prosecutions (DUI/doping), pharmaceutical batch release,
  food-safety decisions.
- **An eCTD / ESG signing root**: FDA submission chain of custody
  compromised. Existing NDAs up for renewal / supplements have
  integrity questions.

Instrument lifecycle is 7–12 years. Firmware root compromise
across a major vendor means a multi-year recalibration + re-
qualification programme across every CAP/CLIA-accredited lab using
that vendor, during which affected assays cannot be used for
patient reporting without parallel paper-process controls.
