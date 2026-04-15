# rfc3161-tsa-timestamp — RSA in the "when did this exist" industry

**Standard:** RFC 3161 Time-Stamp Protocol; ETSI EN 319 422 (qualified timestamps)
**Industry:** Code signing, legal documents, financial archives, patents, eIDAS qualified services
**Algorithm:** RSA-2048 to RSA-4096 (TSA signing keys; SHA-256/384/512 digest)

## What it does

A Time-Stamping Authority (TSA) issues a signed statement that a particular hash
existed at a particular time. The timestamp is itself a CMS SignedData structure
(RFC 5652) with the TSA's RSA signature over the hash-of-document + UTC time +
TSA identity + optional accuracy and serial number.

Used everywhere that a "this existed at time T" proof is needed:

- **Code signing** (Authenticode, Apple, JAR): countersignature extends signature
  validity beyond the signer's cert expiry. Without a timestamp, every signed
  executable becomes "invalid" the day its signing cert expires. Microsoft
  Authenticode countersignature is always RFC 3161.
- **Legal documents**: PDF Advanced Electronic Signatures (PAdES-LTV), eIDAS
  qualified electronic signatures. EU Trusted Lists enumerate qualified TSAs.
- **Financial archives**: SEC 17a-4 / MiFID II require timestamped transaction
  records. Banks use qualified TSAs to satisfy retention regulations.
- **Patent filings**: WIPO, USPTO, EPO all accept timestamped submissions
  (and in some cases require them for priority claims).
- **Long-term archives** (CAdES-A, XAdES-A, PAdES-LTV): archive timestamps
  prove content existed before the signer's cert was revoked.
- **Blockchain anchoring**: some companies timestamp hashes on blockchains,
  but the original RFC 3161 TSA remains the accepted evidence standard for
  legal purposes.

Major operating TSAs:
- DigiCert, Sectigo, GlobalSign, Entrust — web-PKI-trusted TSAs used for
  code signing
- Certum, Swisscom, D-Trust, Quovadis, A-Trust — eIDAS qualified TSAs
- Microsoft, Apple — their own timestamping services for their dev ecosystems
- National TSAs: PostCertum (PL), Infocert (IT), ANF AC (ES)

## Why it's stuck

- RFC 3161 specifies CMS SignedData, with signature algorithms from
  RFC 5754 (SHA-2 family + RSA or ECDSA). ECDSA is permitted but RSA
  dominates deployed TSA keys (CA/Browser Forum code-signing BRs mandate
  specific RSA sizes for CSBR-compliant TSAs).
- The LTV (long-term validation) property means a timestamp issued today
  with RSA-2048 must remain verifiable decades into the future. Historical
  timestamps back to 2002 are still relied upon in archive chains.
- ETSI EN 319 422 (qualified TSA requirements) references RSA-2048 as a
  minimum; qualified TSAs in EU Trusted Lists use it.
- A TSA key rotation invalidates nothing historical (the old signatures
  remain verifiable against the old key as long as the root CA keeps it
  trusted). But the installed base of validation software (Acrobat, Microsoft
  SignTool, signxml, openssl ts, signserver) has RSA baked in.

## impact

a TSA signature is legal evidence that a document or software existed at a specific
time. factor a TSA's signing key and you retroactively insert evidence into the
historical record.

- factor a qualified TSA's RSA-2048 signing key. now forge timestamps for any
  hash and any past timestamp (within cert validity). backdate documents:
  contracts dated "before" a dispute, emails "sent" before a lawsuit, code
  "signed" before a breach was disclosed.
- **code signing anti-forensics**: a compromised software publisher's signing
  cert is revoked with effective date T. Authenticode treats binaries signed
  before T as valid. forge a countersignature with timestamp T-1 on malware
  that was actually created after T — Microsoft SmartScreen and Windows
  Defender accept the binary as signed-before-revocation.
- **forged prior art / patent antedating**: timestamped preservation of technical
  disclosures is the standard way companies establish invention dates for patent
  interference proceedings (USPTO AIA first-to-file notwithstanding, provisional
  applications and reduction-to-practice records still rely on them). a forged
  TSA signature rewrites invention priority.
- **eIDAS qualified signature forgery**: under EU 910/2014, qualified electronic
  signatures have the same legal weight as handwritten signatures and shift the
  burden of proof. forged qualified timestamps create legally binding signed
  contracts the claimed signer never saw.
- **MiFID II / Dodd-Frank evasion**: trading firms are required to timestamp
  order records to the millisecond. forge the TSA's signature to alter the
  historical record of trades, changing execution timestamps to hide front-running
  or to launder MNPI-based trades.
- **cascading archive collapse**: PAdES-LTV documents archive-timestamp
  themselves periodically to survive root CA and signer cert expiry. these
  chains depend on each successive TSA key being uncompromised. factoring any
  TSA key in the archive chain breaks the evidence chain for everything
  timestamped under it, retroactively.
- **EU Trusted Lists** publish every qualified TSA's cert. attackers have full
  access to every qualified TSA's RSA public key, which is exactly what they
  need to start factoring.

## Code

`tsa_rfc3161.py` — `build_timestamp_request()` (RFC 3161 TimeStampReq with
messageImprint = SHA-256(document)), `issue_timestamp()` (TSA-side CMS SignedData
generation with RSA-2048 signature), `verify_timestamp()` (verify TimeStampResp
against TSA cert chain), `build_ltv_archive_chain()` (nested archive-timestamp
for CAdES-A / PAdES-LTV). EU Trusted List model and code-signing countersignature
context in comments.
