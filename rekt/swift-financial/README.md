# swift-financial — RSA in global interbank messaging

**Standard:** SWIFTNet PKI / ISO 20022 XMLDSig 
**Industry:** Banking, financial messaging — SWIFT, TARGET2, Fedwire, CHIPS 
**Algorithm:** RSA-2048 (bank certificates), RSA-4096 (SWIFT Root CA) 

## What it does

SWIFT processes ~44 million financial messages per day (trillions of dollars).
Every SWIFT member institution authenticates with an RSA-2048 X.509 certificate
issued by the SWIFTNet PKI. ISO 20022 MX messages are signed with XMLDSig
(same RSA-only spec as SAML).

Major payment systems all use RSA:
| System | Daily volume | Algorithm |
|---|---|---|
| SWIFT gpi | $5T/day | RSA-2048 certificates |
| TARGET2 (ECB) | €400B/day | RSA-2048 XMLDSig |
| Fedwire (US Fed) | $4T/day | RSA-2048 TLS |
| CHIPS | $1.8T/day | RSA-2048 auth |

## Why it's stuck

The XMLDSig standard (used for ISO 20022 message signing) is RSA-only by
spec — see `saml-ruby/` for the same problem. Financial message signing is
doubly constrained: not only must the W3C update XMLDSig, but all 11,000+
SWIFT member institutions must simultaneously update their signing infrastructure.

SWIFT has participated in NIST non-RSA awareness activities but has not published
a migration timeline. Payment clearing houses (ECB, Fed, BIS) have not mandated
non-RSA. The SWIFT network is a systemic financial infrastructure — a coordinated
non-RSA migration requires a multi-year standards process.

HNDL risk for finance: payment messages are account numbers and amounts, not
secrets — but **non-repudiation** (proving a bank authorized a payment) is
based on RSA signatures. A factoring break undermines the legal basis for disputed payment
disputes.

## impact

SWIFT processes about 44 million messages per day. trillions of dollars. the 2016 Bangladesh Bank heist stole $81 million via social engineering. a factoring attack doesn't need social engineering, just the target bank's published RSA certificate.

- forge a pacs.008 credit transfer appearing to originate from any legitimate bank BIC. unauthorized wire transfer to attacker-controlled accounts, indistinguishable from a real payment instruction
- RSA signatures on MX messages are the legal proof that a bank authorized a payment. forge them and the non-repudiation basis for disputed payment resolution collapses. "we didn't send that" becomes impossible to prove either way
- TARGET2 moves 400 billion euros per day. Fedwire moves 4 trillion dollars per day. forged payment instructions at this level can move sovereign-scale funds before anyone in the clearing chain catches it
- there's no documented playbook for recovering from a mass SWIFT authentication compromise. correspondent banking relationships would freeze globally until authentication could be reestablished
## Code

`swift_mtngs_rsa_signing.java` — `SWIFTMXMessageSigner.signMXMessage()` using
`javax.xml.crypto.dsig` with `SHA256withRSA` and `rsa-sha256` XMLDSig URI,
with commentary on TARGET2, Fedwire, CHIPS, and the non-repudiation risk.
