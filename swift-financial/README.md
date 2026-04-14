# swift-financial — RSA in global interbank messaging

**Standard:** SWIFTNet PKI / ISO 20022 XMLDSig  
**Industry:** Banking, financial messaging — SWIFT, TARGET2, Fedwire, CHIPS  
**Algorithm:** RSA-2048 (bank certificates), RSA-4096 (SWIFT Root CA)  
**PQC migration plan:** None — W3C XMLDSig has no PQC URI; SWIFT has published awareness but no migration plan

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

SWIFT has participated in NIST PQC awareness activities but has not published
a migration timeline. Payment clearing houses (ECB, Fed, BIS) have not mandated
PQC. The SWIFT network is a systemic financial infrastructure — a coordinated
PQC migration requires a multi-year standards process.

HNDL risk for finance: payment messages are account numbers and amounts, not
secrets — but **non-repudiation** (proving a bank authorized a payment) is
based on RSA signatures. A CRQC undermines the legal basis for disputed payment
disputes.

## Code

`swift_mtngs_rsa_signing.java` — `SWIFTMXMessageSigner.signMXMessage()` using
`javax.xml.crypto.dsig` with `SHA256withRSA` and `rsa-sha256` XMLDSig URI,
with commentary on TARGET2, Fedwire, CHIPS, and the non-repudiation risk.
