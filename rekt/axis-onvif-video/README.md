# Video surveillance — ONVIF / SRTP with signed firmware, video-
# evidence chain-of-custody signatures

Commercial and public-safety video surveillance runs on a fleet of
**~1 billion installed surveillance cameras worldwide** (IHS Markit
/ Omdia). Major vendors:

- **Axis Communications** (market leader in Western enterprise +
  public-safety verticals)
- **Hikvision / Dahua** (Chinese vendors, ~50% global unit share;
  US NDAA Section 889 restricted)
- **Hanwha Vision** (formerly Samsung Techwin, South Korea)
- **Bosch Security** / **Honeywell** / **Pelco** (enterprise)
- **Avigilon / Motorola Solutions**, **Verkada**, **Eagle Eye
  Networks** (cloud VMS)
- **Arlo / Ring / Nest** (consumer but penetrating SMB)

Behind the cameras: a **VMS (Video Management System)** — Genetec
Security Center, Milestone XProtect, Avigilon Control Center,
Verkada Command, BriefCam, Dahua DSS — plus a body-worn camera
fleet and related evidence-management software (see
`axon-bodycam-evidence/`).

## Standards

- **ONVIF Profile S / T / G / M** — device discovery, streaming,
  PTZ, analytics, metadata. WS-Security with XMLDSig for config
  commands.
- **SRTP** for media (symmetric per-stream keys, but negotiated via
  TLS / DTLS handshakes anchored in RSA-backed certs).
- **IEC 62676-2 / -4** (video surveillance systems).
- **FIPS 140-2 / CC EAL** for federal / DoD deployments.
- **MISB ST 0902 / UAS metadata** for ISR / defence-grade video.

## RSA usage

### 1. Camera firmware signing
Every modern camera above ships RSA-signed firmware. Axis AXIS OS,
Hikvision HIK-Connect, Bosch INTEOX, Hanwha Wisenet WAVE, Verkada's
locked-down Linux — all boot-verify signatures.

### 2. Video-stream authentication (ONVIF + VMS)
Camera-to-VMS mutual TLS with RSA-2048+ client certs. Enterprise
deployments (hospitals, banks, airports) require per-camera certs
from an internal PKI, often integrated with Microsoft ADCS or
HashiCorp Vault PKI. Configuration messages (PTZ commands, analytic
rule changes) are XMLDSig-signed under ONVIF.

### 3. Video-evidence signing (chain-of-custody)
Recorded clips retained for evidentiary use are signed — JPEG-2000
or H.264 container with a detached PKCS#7 signature over the frame
hashes + metadata. **Axis Signed Video** (published 2021) and
**C2PA Content Credentials** (broader industry initiative) both use
RSA/ECDSA to bind the camera identity to every frame. US federal
courts have admitted Axis-signed video under F.R.E. 901
authentication.

### 4. ONVIF device discovery / WS-Security
ONVIF's SOAP-based management runs over WS-Security `X509Token`
with RSA signatures on configuration-change messages. Enterprise
camera-admin consoles (Genetec, Milestone) use this.

### 5. Motorola / Avigilon / Verkada cloud
Cloud-VMS platforms (Verkada Command, Eagle Eye Networks, Avigilon
Unity Cloud, Motorola Orchestrate) each have a per-camera
enrollment CA that issues RSA client certs at install time.

### 6. Facial-recognition / LPR confidence signing
ALPR systems (Vigilant/Motorola, Genetec AutoVu, Flock Safety)
sign every read with plate + jurisdiction + confidence before
uploading to the operator DB — evidentiary integrity for
downstream police use.

## Scale

- ~1 billion installed surveillance cameras worldwide
- US federal / DoD / NDAA-restricted: ~5M of those (excludes
  Hikvision / Dahua / Huawei / Dahua-OEM-rebrand)
- Axis public-safety installed base: ~60M
- Verkada: ~300k cloud cameras across ~20k enterprise customers
  (note the 2021 breach where ~150k camera feeds were exposed via
  a super-admin credential — the cryptographic trust chain held
  but out-of-band credential compromise bypassed it)

## Breakage

A factoring attack against:

- **An Axis / Hikvision / Dahua / Bosch / Hanwha firmware root**:
  signed firmware pushed to millions of cameras that streams
  into attacker infrastructure (Mirai-class botnet, nation-
  state ISR capability), or that silently disables tamper-
  evidence on video sent to law enforcement. Video-evidence
  integrity in the criminal-justice system is undermined.
- **A video-evidence signing root (Axis Signed Video, C2PA)**:
  forgery of "authenticated" surveillance footage. In court:
  "verified by camera 12345" becomes plantable. Exoneration-
  review cases (Innocence Project etc) lose their integrity
  anchor for new signed-video evidence.
- **A cloud-VMS enrollment CA (Verkada, Eagle Eye, Motorola)**:
  attacker mints camera certs, spoofs a legitimate camera to
  the cloud to poison the archive; or impersonates the cloud
  to a camera to exfiltrate recent footage.
- **An ALPR signing root (Flock Safety, Vigilant)**: forged
  plate-reads place an innocent vehicle at a crime scene;
  cleared/wanted vehicles mis-flagged at scale.

Surveillance-camera lifecycle is 7–15 years. In practice most
cameras never get firmware updates after year 3; the rotational
half-life of signing-key compromise is unusually long in this
sector.
