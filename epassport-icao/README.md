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

## impact

1.2 billion passports in circulation, 10-year validity. chips issued today will still be active in 2035. the whole global border security model sits on RSA being hard to break.

- recover any country's CSCA RSA private key and produce SODs that pass verification at every border in the world. forge passports from any country, at scale
- the Active Authentication public key is on the chip and readable by any NFC reader. a CRQC recovers the AA private key and the chip clone passes active authentication. the document fraud is completely invisible
- border control systems pull CSCA keys from the ICAO PKD and trust them unconditionally. a forged SOD looks exactly like a real one because the RSA signature is valid
- this is jurisdiction-wide mass identity fraud rather than individual forgeries. every passport from a compromised country's CSCA, all at once
## Code

`icao_9303_passive_auth.c` — `icao_passive_authentication()` (CMS RSA verify)
and `icao_active_authentication()` (RSA-1024/2048 chip signing) with notes on
the CSCA hierarchy and HNDL risk to border control systems.
