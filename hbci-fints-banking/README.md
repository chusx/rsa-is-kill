# hbci-fints-banking — RSA-2048 in German HBCI/FinTS online banking (80M accounts)

**Repository:** python-fints (raphaelm/python-fints), aqbanking (aquamaniac.de); FinTS 4.1 spec (Deutsche Kreditwirtschaft)  
**Industry:** German retail and business banking — Sparkassen, Volksbanken, Deutsche Bank, Commerzbank  
**Algorithm:** RSA-2048 (RDH-10 profile — authentication key and encryption key)  
**PQC migration plan:** None — FinTS 4.1 was last updated in 2017; ZKA/DK (Deutsche Kreditwirtschaft) has not published a PQC migration for FinTS; the RDH-10 profile is normative with no planned revision

## What it does

HBCI (Homebanking Computer Interface) / FinTS is the German banking industry standard for
online banking APIs. It's used for programmatic bank access by accounting software, ERP
systems, personal finance tools, and direct banking clients.

The security profile RDH-10 (RSA Diffie-Hellman profile 10) uses RSA-2048 for both
message authentication (PKCS#1 v1.5 signatures on FinTS message headers) and message
encryption (RSA-PKCS1v15 session key wrapping for AES-256). Every FinTS RDH transaction
is signed with the customer's RSA-2048 authentication key. The bank verifies this before
processing any transaction. The bank's own responses are also RSA-signed.

Deployed at:
- Sparkassen (~50M customer accounts, Germany's largest banking group)
- Volksbanken/Raiffeisenbanken (~30M accounts)
- Deutsche Bank, Commerzbank, Postbank business banking
- DATEV — ~80% of German tax advisors and accountants, all using HBCI for payroll/booking
- GnuCash, KMyMoney, Hibiscus — open-source finance clients with aqbanking
- Every German ERP integration that pulls bank statements automatically

The customer's RSA public key is registered with their bank during initial setup and
is stored in the bank's backend. It's also in the customer's keyfile (a local binary file).
The bank's RSA public key is in the customer's keyfile too. Both are available for CRQC.

## Why it's stuck

- FinTS 4.1 is controlled by the Deutsche Kreditwirtschaft (DK), the consortium of
  German banking associations. Updating the protocol spec requires consensus across
  all member associations: BdB, DSGV (Sparkassen), BVR (Volksbanken), DZ Bank, etc.
  This process is measured in years.
- aqbanking and python-fints implement FinTS as specified. Until DK publishes a FinTS 4.2
  or 5.0 with PQC key types, there's nothing for the libraries to implement.
- Customer keyfiles are in a proprietary binary format (different per banking software).
  Millions of existing keyfiles contain RSA-2048 keys. Key rollover requires each customer
  to re-register with their bank using a new key — a manual process many won't do.
- The banking servers at every Sparkasse and Volksbank would need to be updated to accept
  PQC-signed FinTS messages. German banking IT moves slowly; core banking systems at
  Sparkassen often run decades-old software.

## impact

HBCI/FinTS RDH is online banking authentication for German businesses. the RSA signature
is what authorizes wire transfers. no additional factors required.

- factor a customer's RSA-2048 authentication key. it's in their keyfile (often backed up
  to cloud storage or emailed to themselves), and the public key is registered with the bank.
  now you can send FinTS HKUEB (wire transfer) messages signed with their key. the bank
  verifies the RSA signature, sees it's valid, processes the transfer. no OTP. no 2FA.
  just RSA.
- DATEV integration: tax advisors with HBCI access to client accounts can initiate payroll
  transfers, book tax payments, check balances. DATEV is used for ~40% of German GDP in
  payroll processing. the RSA key on a DATEV terminal authenticates all of this.
- harvest now: record FinTS sessions (they use TLS, but the bank's RSA encryption key
  is in the keyfile). when CRQC arrives, factor the bank's RSA-2048 encryption key,
  decrypt all recorded sessions. every wire transfer, every balance, every transaction
  history for every customer you recorded — all of it.
- bank response forgery: factor the bank's RSA auth key. forge bank responses — fake
  balance confirmations, fake transaction rejection notices (transfer went through but
  you told the customer it failed). a whole class of fraud that currently requires
  compromising the bank's systems; with RSA broken, it requires only the bank's public key.

## Code

`hbci_rsa_auth.py` — `hbci_sign_message()` (RSA-SHA256 PKCS#1 v1.5 FinTS message signing),
`hbci_verify_bank_response()` (bank response RSA signature verification), `hbci_encrypt_message()`
(RSA-PKCS1v15 session key wrapping + AES-256 encryption). python-fints / aqbanking context.
FinTS 4.1 RDH-10 profile per Deutsche Kreditwirtschaft specification.
