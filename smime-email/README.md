# smime-email — RSA in enterprise email signing and encryption

**Standard:** S/MIME v4.0 (RFC 8551), CMS (RFC 5652)  
**Industry:** Enterprise email, government, healthcare, legal, banking  
**Algorithm:** RSA-2048 / RSA-4096 (signing and key encipherment)  
**PQC migration plan:** None — RFC 8551 is RSA-only; IETF LAMPS WG has PQC S/MIME drafts, no RFC published

## What it does

S/MIME is the standard for digitally signed and encrypted email. It's built into
Microsoft Outlook, Apple Mail, Thunderbird with Enigmail, and every enterprise
email gateway.

Where S/MIME is used:
- **US DoD** — CAC/PIV cards include S/MIME certificates for CUI email. All
  department-to-department official email uses S/MIME
- **EU eIDAS** — Qualified Electronic Signatures on email have legal standing
  equivalent to handwritten signatures in EU member states
- **Healthcare (HIPAA)** — secure messaging between covered entities; many
  EHR vendors use S/MIME for patient record transfers
- **Banking/finance** — internal and inter-bank secure messaging
- **German government (BSI TR-03108)** — DE-Mail uses S/MIME, federal agencies
  mandated to use S/MIME for official correspondence
- **Legal** — law firms use S/MIME for attorney-client privileged email

S/MIME uses PKCS#7 (CMS) SignedData for signatures and EnvelopedData for
encryption. Encryption uses RSA to wrap a per-message AES-256 content key.
Unlike TLS (which uses ephemeral keys), S/MIME encryption is persistent:
the same RSA key encrypts potentially years of email.

## Why it's stuck

- RFC 8551 (S/MIME v4.0, 2019) specifies only RSA for key transport and signing.
  No PQC algorithm OID is defined in the S/MIME standard
- IETF LAMPS WG has published draft-ietf-lamps-pq-composite-sigs and related
  drafts for PQC in CMS/S/MIME, but none are RFC yet
- Every S/MIME email client (Outlook, Apple Mail) would need updates to support
  PQC certificates. Email clients update slowly, especially in enterprise deployments
- Enterprise CA infrastructure (ADCS, Entrust, DigiCert) does not issue
  PQC S/MIME certificates
- Government and regulated industries have certificate profiles that specify
  RSA-2048 — changing the algorithm requires regulatory approval cycles

## impact

S/MIME is used for the kind of email that nobody wants decrypted: attorney-client
privilege, classified-adjacent government communication, HIPAA patient data,
bank-to-bank transfers. also, S/MIME encryption is persistent, unlike TLS.
every archived encrypted email is future HNDL bait.

- factor any individual's RSA-2048 S/MIME certificate (public in email headers, in
  corporate LDAP, in CAC certificate databases) and decrypt every email ever sent to
  them encrypted with that key. inbox fully compromised, retroactively and indefinitely
- US DoD uses CAC S/MIME for CUI email. those certificates are RSA-2048, and the
  corresponding encrypted emails are sitting in mail servers, backup tapes, and
  government archive systems. all retroactively decryptable
- forge S/MIME signatures on email. send a signed email appearing to be from any
  person whose certificate you have. the signature verifies. no indication of forgery
- German federal agencies, EU legal proceedings, HIPAA records: the legal standing
  of signed S/MIME email collapses once signatures are forgeable. every archived signed
  email's authenticity is retroactively questionable

## Code

`smime_rsa_sign.c` — `smime_sign()` (CMS_sign() creating RSA-signed SignedData),
`smime_encrypt()` (CMS_encrypt() wrapping AES key with RSA-OAEP), and notes on
DoD CAC S/MIME usage and HNDL risk for long-term encrypted email archives.
