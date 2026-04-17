# ICAO 9303 e-Passport — Document Signer / Country Signing CA

Every biometric passport issued since ~2006 is an ICAO 9303 MRTD
with an embedded RSA / ECDSA key pair and a signed **Document
Security Object (SOD)** covering the fingerprint, face image, and
biographic data groups. **~1.5 billion e-passports currently in
circulation across 170+ issuing states.**

## RSA usage

### 1. Country Signing CA (CSCA)
Each state operates an offline CSCA — hardened HSM, air-gapped,
ceremony-signed. CSCA lifetime is typically 10+ years; CSCA roots
are exchanged between states via the **ICAO Public Key Directory
(PKD)** and diplomatic channels. Vast majority of CSCAs still use
RSA-4096. Migration to ECC has been discussed since 2015 and has
not happened at scale because every ICAO-conformant inspection
kiosk in the world has to keep verifying legacy documents for 10
years after the last one is issued.

### 2. Document Signer (DS)
CSCA issues short-lived DS certs (90–180 day issuance cycle) held
in the passport production HSM. Each chip has the DS cert embedded
and an SOD signed by the DS over the SHA-256 hashes of each DG
(Data Group): DG1 biographic, DG2 face image, DG3 fingerprints,
DG14 PACE/CA parameters, DG15 AA public key.

### 3. Active Authentication (AA)
Optional anti-cloning: chip holds a per-chip RSA key, signs an
inspection-system challenge. Still widely deployed (EU, Japan,
Korea) rather than replaced by ECDSA.

### 4. Terminal Authentication (EAC)
Access to fingerprint DG3 restricted to inspection terminals
authorised by the issuing state. Terminal presents a cert chain
(CVCA → DVCA → Terminal) — still RSA-2048 in most deployments.

## Scale + stickiness

- 1.5 B e-passports, ~250M issued/year
- ICAO PKD: 90+ participating states
- EU Entry/Exit System (EES) live 2024+ reads e-passports at
  every Schengen external border (~700M crossings/yr)
- CBP Global Entry / APC kiosks; every major airport worldwide

Why RSA doesn't move: chips already in circulation cannot be
updated. Border kiosks must keep verifying for the full 10-year
validity of every issued document. DS rotation is annual at many
states; CSCA rotation takes a decade. A migration would roll out
over 20+ years minimum.

## Breakage

- **CSCA factored**: attacker mints DS certs, produces e-passports
  that border systems accept as authentic — any name, any photo,
  any nationality. Criminal + counter-terrorism implications are
  direct. ICAO PKD trust relationships between states collapse.
- **DS key factored (a 90-day window)**: batch of forged
  passports for that state / that issuing run. Detection is
  eventual via PKD CRL but forgeries already in circulation stay
  usable until chip revocation propagates (which it often doesn't
  — many kiosks don't do online cert status).
- **AA key factored (per-chip)**: chip-cloning capability against
  that document; less than CSCA-scale impact.
- **Terminal CVCA factored**: unauthorised access to fingerprint
  DG3 worldwide on EAC-protected documents.

Replacement path: bilateral CSCA roll + PKD re-publication + new
DS chains + kiosk trust-store push. The Netherlands CSCA roll
(2016) took ~18 months for partner-state propagation; a
factoring-break demand for emergency rotation across every ICAO
state is without precedent.
