# epassport-icao — RSA in 1.2 billion travel documents

**Standard:** ICAO Doc 9303 Part 11 (e-Passport / eMRTD security mechanisms)  
**Industry:** Government identity, border control, travel  
**Algorithm:** RSA-2048/4096 (CSCA, Passive Auth), RSA-1024/2048 (Active Auth chip)  
**PQC migration plan:** None — no PQC mechanism in ICAO 9303 or BSI TR-03110

## What it does

E-passports (ICAO eMRTDs) contain an NFC chip that stores biometric data
(photo, fingerprints) protected by three cryptographic mechanisms:

1. **Passive Authentication (PA)**: A Document Security Object (SOD) is signed
   by the issuing country's Country Signing CA (CSCA) using RSA or ECDSA.
   The SOD contains SHA-256 hashes of all data groups. Verifying the SOD
   proves the chip data is genuine.

2. **Active Authentication (AA)**: The chip holds an RSA-1024 or RSA-2048
   private key burned at personalization. Border control sends a random
   challenge; the chip signs it with RSA, proving the chip is not cloned.

3. **Chip Authentication (CA)**: ECDH-based secure messaging.

~1.2 billion e-passports are in circulation (2024). Passport validity: 10 years.
The chips cannot be updated after the passport is issued.

## Why it's stuck

- 195 ICAO member states each operate a CSCA with RSA/ECDSA signing keys
- All CSCA public keys are published in the ICAO PKD at `pkd.icao.int`
- Forging a SOD from any country requires only the CSCA public key + a CRQC
- The ICAO PKD has no PQC certificate format defined
- Chip Active Authentication uses RSA hardwired in silicon (no update possible)
- Migrating requires issuing new passports to ~1.2 billion people

A CRQC attacking passive authentication: factor any CSCA's RSA key → forge
any passport from that country. Border control terminals worldwide would accept
the forgery. A CRQC attacking Active Authentication: clone any passport chip
by factoring its AA public key from EF.DG15.

## why is this hella bad

- **Forge passports from any country**: recover any country's CSCA RSA private key → produce SODs that pass verification at every border worldwide
- **Clone any passport chip**: the AA public key is on the chip and readable by any NFC reader → CRQC recovers AA private key → chip clone passes active authentication → invisible document fraud
- Border control systems worldwide pull CSCA keys from the ICAO PKD and trust them completely; there is no behavioral anomaly to detect a forged SOD
- ~1.2 billion passports in circulation, 10-year validity — chips issued today will still be active in 2035
- This attack enables **jurisdiction-wide mass identity fraud** (every passport from a compromised country) rather than individual document forgery

## Code

`icao_9303_passive_auth.c` — `icao_passive_authentication()` (CMS RSA verify)
and `icao_active_authentication()` (RSA-1024/2048 chip signing) with notes on
the CSCA hierarchy and HNDL risk to border control systems.
