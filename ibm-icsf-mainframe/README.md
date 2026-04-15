# ibm-icsf-mainframe — RSA in z/OS mainframe cryptography (COBOL)

**Software:** IBM ICSF (Integrated Cryptographic Service Facility) on z/OS  
**Industry:** Banking, insurance, government — every major bank runs z/OS  
**Algorithm:** RSA-2048 / RSA-4096 (PKCS#1 v1.5 and OAEP) via CEX coprocessor hardware  
**PQC migration plan:** None — no ICSF callable service for any NIST PQC algorithm; IBM z/OS 3.1 mentions "PQC exploration" with no shipped capability

## What it does

IBM z/OS mainframes process an estimated 30 billion transactions per day globally.
ICSF is the cryptographic subsystem for z/OS — COBOL, PL/I, and assembler programs
call ICSF callable services (verbs) to perform RSA operations. The actual computation
runs on the CEX (Crypto Express) hardware coprocessor cards installed in the mainframe.

ICSF RSA callable services:
- `CSNDRSA` — Digital Signature Generate (RSA PKCS#1 v1.5 or PSS signing)
- `CSNDRSV` — Digital Signature Verify
- `CSNDPKE` — PKA Encrypt (RSA-OAEP key wrapping)
- `CSNDPKD` — PKA Decrypt (RSA-OAEP key unwrapping)
- `CSNDPKG` — PKA Key Generate (RSA-2048/4096 keypair generation in hardware)

RSA is used on z/OS for:
- **SWIFT/ACH payment signing** — COBOL programs call `CSNDRSA` to sign payment instructions
- **HSM key wrapping** — RSA-OAEP wraps 3DES and AES master keys in the key hierarchy
- **TLS server certificates** — AT-TLS (Application Transparent TLS) on z/OS uses RSA-2048
- **Digital signature on regulatory filings** — EDGAR, bank regulatory reports
- **Inter-system key exchange** — RSA wraps DES/AES session keys between CICS regions

The CEX7S and CEX8S cards (IBM Z16 / z15) accelerate RSA with dedicated hardware.
These cards have no ML-DSA or ML-KEM accelerator and no firmware path to add one.

## Why it's stuck

- ICSF has been on z/OS since 1990. COBOL programs written in the 1990s call `CSNDRSA`
  and will continue calling it until the bank replaces the program
- IBM has published no ICSF callable service for ML-DSA, ML-KEM, or any NIST PQC algorithm
- The CEX hardware coprocessor has no PQC algorithm support. IBM would need new firmware
  for existing cards or new hardware entirely
- z/OS application migrations take years: regulatory testing, parallel running, sign-off
  from multiple banking regulators (OCC, FDIC, BaFin, PRA, etc.)
- IBM's CRYSTALS-Kyber/Dilithium exploration (published 2022) is research-level.
  Nothing is in the z/OS GA roadmap with a ship date

## impact

z/OS is where actual money moves. not the web app, not the microservice — the COBOL
program calling CSNDRSA at the bottom of the stack. 30 billion transactions per day.

- ICSF RSA private keys live in the CEX coprocessor hardware. a CRQC doesn't extract
  them from hardware, it derives them from the public key (available in the certificate
  on the AT-TLS connection, or in the PKA public key token used for key wrapping).
  the hardware security model is entirely irrelevant to Shor's algorithm
- SWIFT payment signing on z/OS uses `CSNDRSA`. factor the bank's RSA key and you can
  sign arbitrary SWIFT payment instructions that appear to originate from that bank's
  z/OS system. this is the COBOL-level equivalent of the swift-financial example —
  the same RSA, deeper in the stack
- RSA-OAEP key wrapping (CSNDPKE) is how z/OS protects DES and AES master keys in
  transit between CICS regions. break RSA, unwrap the master keys, decrypt everything
  they protect in the entire key hierarchy
- the COBOL programs calling these verbs are not getting rewritten on any short timeline.
  the z/OS PQC migration is probably the slowest migration in this entire repo. the
  regulatory approval cycle alone is measured in years

## Code

`icsf_rsa_cobol.cbl` — COBOL program calling `CSNDPKG` (RSA-2048 keypair generation),
`CSNDRSA` (PKCS#1 v1.5 digital signature generate), and `CSNDPKE` (RSA-OAEP session
key wrapping), with notes on CEX hardware coprocessor limitations.
