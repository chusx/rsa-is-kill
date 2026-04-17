# IAEA nuclear safeguards — remote monitoring + seal CoK

The International Atomic Energy Agency's **Department of Safeguards**
runs a global regime verifying that declared nuclear material and
facilities are not diverted for weapons use, under the **NPT**
(Non-Proliferation Treaty), **Comprehensive Safeguards Agreements**,
and the **Additional Protocol**. Field operations depend on a
hierarchy of remote-monitoring and authenticated-sealing systems —
all of which carry RSA signatures to preserve Continuity of
Knowledge (**CoK**) between inspector visits.

Deployed at ~1,300 safeguarded facilities worldwide: reactor sites
across US/France/Japan/Korea/UK/Russia/India/China (declared),
enrichment facilities (URENCO Almelo / Gronau / Capenhurst, Natanz,
Rokkasho), reprocessing plants (La Hague, Sellafield THORP legacy,
Tokai), spent-fuel-pool installations, research reactors, uranium
conversion plants. In 2022 the IAEA performed ~14,500 inspector-days
and analyzed ~900,000 environmental-swipe samples; remote-monitoring
systems carry the long-tail continuity burden between visits.

## RSA-dependent safeguards systems

### 1. Digital Cerenkov Viewing Device (DCVD) — spent-fuel verify
DCVD images of spent-fuel assemblies are signed by the device's
RSA private key at capture, so inspectors can prove images have
not been altered before analysis at IAEA HQ Vienna.

### 2. Next-Generation Surveillance System (NGSS / XCAM family)
Pan-tilt-zoom or static cameras positioned on critical containment
paths. Every video frame is RSA-signed by the in-camera HSM. Tamper
events and power-loss events are logged into signed audit streams.

### 3. Electronic Optical Seals — VACOSS, EOSS, EBMS
"Electronic Optical Sealing System" and variants consist of a
fiber-optic loop through a containment item (shipping cask,
material container), a sealing body with an HSM, and an RSA-signed
seal integrity record. A broken fiber loop (seal compromise) is
logged and the log is signed so tampering with the log itself is
detectable. Inspectors read the seal at each visit, verify the
signature, and upload to IAEA HQ.

### 4. Unattended Monitoring Systems (UMS) at enrichment plants
Gas-centrifuge cascades at Rokkasho, Almelo, Capenhurst are fitted
with UMS that signs continuous UF6 flow / enrichment measurements
and stores signed logs on-site. Inspectors retrieve the logs on
quarterly visits; the IAEA HQ analysis pipeline verifies every
signature before admitting the data into the safeguards record.

### 5. Secure Data Transmission (SDT)
Some sites allow "remote-data-transmission" of inspection data to
IAEA HQ over VSAT/commercial internet links. Each packet is
RSA-signed by the on-site sender and optionally double-enveloped
in TLS mutual-auth. SDT is in production at European Commission
Joint Research Centre ITU facilities, plus select commercial
European power-reactor sites.

### 6. Inspector authentication + chain-of-custody
Inspector identity cards are PKI-based with RSA-2048 keypairs,
issued by the IAEA internal PKI. Field laptops and inspection
software (Mini-Inspector, CoTeN, Nucleus) validate the inspector's
cert at every access to sample-tracking databases.

## Scale and consequence

- ~1,300 safeguarded facilities under INFCIRC/66 or INFCIRC/153
  agreements
- ~45,000 electronic seals and surveillance instruments in field
- Safeguards budget ~€150M/year
- The continuity of the **Non-Proliferation regime** depends on
  these signatures being trustworthy: if CoK fails, declared
  material cannot be distinguished from undeclared diversion.

## Breakage

A factoring attack against:

- **The IAEA safeguards-equipment root CA** (the key that signs
  NGSS camera, VACOSS seal, and UMS device certificates): attacker
  mints forged safeguards instruments, or forges post-hoc signed
  measurement records matching the expected instrument signature.
  **Continuity of Knowledge collapses.** A diverted enrichment run
  or a swapped spent-fuel assembly becomes undetectable from
  within the safeguards record. This is the cryptographic
  precondition for covert proliferation at a previously-safeguarded
  site.
- **The IAEA inspector PKI root**: forged inspector identity cards
  with access to sample-tracking and inventory-difference systems;
  could corrupt the agency's internal audit trail and mask
  anomalies.
- **A vendor firmware-signing key** (Canberra/Mirion, Aquila,
  Arktis): push backdoored firmware into safeguards instruments
  that silently signs forged measurements.

Safeguards instruments are 10-15 year deployed; equipment replacement
requires facility access negotiation with host states and takes
years. A factoring break creates a non-remediable window during
which the non-proliferation regime's cryptographic integrity is
suspect — which has consequences for the political trust that
underpins INF agreements generally.
