# Body-worn cameras + digital-evidence management — signed video,
# CJIS-compliant chain-of-custody, in-car video-system integration

Law-enforcement body-worn camera (BWC) deployment accelerated
post-2014 Ferguson; US federal DOJ COPS Office grants drove
broad rollout. Current US market:

- **Axon Enterprise** (formerly TASER International) — dominant;
  Axon Body 3/4, Axon Fleet 3 in-car, Axon Evidence (evidence.com)
  cloud DEMS. Axon equips 17 of top 20 US cities' PDs.
- **Motorola Solutions** — WatchGuard (V300, VB400), CommandCentral
- **Getac** — BC-04/BC-02, VR-X20
- **Panasonic / Arbitrator**
- **Reveal**, **Safety Vision**, **Wolfcom**, **Transcend DrivePro
  Body**
- **Digital Ally**, **Visual Labs**

Outside US: UK, Canada, Australia, Germany, France, India rolling
out BWC. Europol / Interpol use Axon Evidence-equivalents. Private
security, utility field crews, hospital security also deploy BWC.

Adjacent: **in-car video** (WatchGuard 4RE, Axon Fleet 3),
**interview-room recording** (Axon Interview, i-Sight), and
**drone+BWC aerial** (Axon Air, Skydio for Enterprise).

## RSA usage

### 1. BWC + in-car firmware signing
Every BWC and in-car system ships RSA-signed firmware. Tamper-
evident boot on the SoC (Qualcomm, Ambarella, HiSilicon).

### 2. Per-clip video signing (chain-of-custody)
At upload to the DEMS (Digital Evidence Management System), the
BWC signs each clip with its per-device RSA key. Clip signature
binds: device serial, officer login, timestamp, GNSS, clip SHA-256.
Under F.R.E. 901, F.R.E. 902(13)-(14) and state-level equivalents
the signed clip is admitted with reduced foundation requirements.

### 3. DEMS ingest TLS mutual auth
BWC → dock → DEMS cloud ingest. Per-device RSA certs on the
upload dock; DEMS side holds the issuing CA.

### 4. CJIS-compliant identity / audit
FBI CJIS Security Policy 5.9 mandates advanced authentication
for access to Criminal Justice Information. DEMS and RMS (Records
Management Systems — Tyler, Mark43, Niche) integrate with the
state's CJIS-conformant SSO, typically SAML RS256 or OIDC RS256
with RSA keys bound to the officer.

### 5. Disclosure / redaction chain
Redacted clips for public / FOIA / discovery release carry a
signature from the redaction tool (Axon Redaction Studio,
VeriPic). Original vs redacted binding is proved by a signed
manifest so the defense can verify the derived clip came from
a specific authenticated original.

### 6. Court-submission signed packages
Export to prosecutor (e.g. Thomson Reuters CaseLogistix, Relativity,
Everlaw) carries a signed envelope. Many state e-filing systems
(Tyler Odyssey, ImageSoft) accept digitally-signed court packages.

## Scale

- ~750k sworn US law-enforcement officers; ~60% now BWC-equipped
- Axon evidence.com stores >300 petabytes of police video
- Body-cam hours uploaded per day in the US: ~5M+
- BWC evidence is foundational in ~50k+ US criminal cases/year

## Breakage

A factoring attack against:

- **A BWC-vendor firmware root** (Axon, Motorola, Getac):
  signed firmware pushed fleet-wide that (a) silently disables
  per-clip signing — all subsequent video loses F.R.E. 902
  self-authentication; (b) allows a rogue "post-record edit"
  workflow; or (c) exfiltrates footage. Criminal-justice
  reliance on BWC collapses.
- **A per-clip / DEMS issuing CA** (Axon evidence.com's
  per-device CA): attacker mints device certs and produces
  signed-video forgeries introduced into evidence. Defense
  motions to exclude become routinely successful; already-
  convicted cases open to habeas review based on signature
  integrity challenges.
- **A CJIS federation signing key**: DEMS access audit trail
  is forgeable. Who viewed / downloaded / exported evidence is
  no longer reliably attributable — a major accountability
  breach given misuse-of-police-information cases.
- **Redaction-tool signing root**: redacted disclosures cannot
  be cryptographically tied to originals; chain-of-custody
  between discovery-produced and booking-uploaded clips
  becomes contestable.
- **Court-package signing root**: filed evidence admitted under
  state e-filing trust-anchor rules is open to re-examination.

BWC / in-car equipment lifecycle: 3–6 years; DEMS backends
retain data for 5–99 years depending on case disposition
(capital-case evidence is retained indefinitely). A
cryptographic break has effects spanning decades.
