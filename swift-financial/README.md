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

## why is this hella bad

SWIFT is the authentication layer for the global interbank payment system. Breaking RSA signatures on payment messages means:

- **Forge payment instructions from any bank**: forge a pacs.008 credit transfer appearing to originate from a legitimate BIC (bank identifier code) → unauthorized wire transfer to attacker-controlled accounts
- **Non-repudiation collapse**: RSA signatures on MX messages are the legal proof that a bank authorized a payment. Forging them destroys the legal foundation for disputed payment resolution
- **Central bank targeting**: TARGET2 (€400B/day) and Fedwire ($4T/day) use RSA-secured connectivity. A forged payment instruction at this level can move sovereign-scale funds
- Precedent: the 2016 Bangladesh Bank SWIFT heist stole $81M via social engineering. A CRQC attack would not require social engineering — just the target bank's published RSA certificate
- Recovery from a large-scale SWIFT authentication compromise has no playbook; correspondent banking relationships would freeze globally until authentication is reestablished

## Code

`swift_mtngs_rsa_signing.java` — `SWIFTMXMessageSigner.signMXMessage()` using
`javax.xml.crypto.dsig` with `SHA256withRSA` and `rsa-sha256` XMLDSig URI,
with commentary on TARGET2, Fedwire, CHIPS, and the non-repudiation risk.
