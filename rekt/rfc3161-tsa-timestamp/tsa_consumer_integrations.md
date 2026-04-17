# RFC 3161 TSA — where the `tsa_rfc3161.py` primitive is actually used

A Time Stamp Authority issues RFC 3161 TimeStampToken structures:
a CMS SignedData whose signed content is a TSTInfo structure
binding a user-supplied hash to a UTC time.  Every TSA signs its
tokens with an RSA-2048+ key (the long-term archival-validity
property that consumers care about is exactly what an RSA factoring
attack kills).

## Commercial TSAs

- **DigiCert TSA** — `http://timestamp.digicert.com`. The default
  countersigner in Microsoft Authenticode signing pipelines, signtool
  defaults, Adobe PDF signing, iText, Jarsigner. Operates RSA-2048
  and RSA-4096 hierarchy.
- **Sectigo TSA**, **Entrust TSA**, **GlobalSign Timestamping CA** —
  same shape, same operator class.
- **SwissSign TSA**, **D-Trust TSA**, **Actalis TSA** — European
  eIDAS qualified-TSP timestamping, used in PAdES-B-LTA qualified
  electronic signature workflows.
- **Apple TSA** — internal TSA used by Apple for macOS notarization
  bundles.
- **Adobe Approved Trust List TSAs** — Adobe maintains a curated list
  of TSAs whose timestamps Reader will treat as "verified for
  long-term"; the AATL list is baked into Reader binaries.

## Consumer code paths

### Authenticode signing (`authenticode-pe/`)
`signtool /tr http://timestamp.digicert.com /td sha256 …` fetches a
TimeStampToken; the token is attached to the PE's `IMAGE_DIRECTORY_
ENTRY_SECURITY` alongside the code-signing certificate. Windows
Defender / SmartScreen / AppLocker all treat a valid TSA
countersignature as the determinant of "was this signature valid at
signing time" even after the code-signing cert expires.

### Jarsigner signing (`openjdk-jarsigner/`)
`jarsigner -tsa …` adds a `Signature Timestamp` attribute to the
PKCS#7 inside `META-INF/`.

### PDF PAdES-B-LTA (`pdf-itext/`)
Every qualified signature in a PAdES long-term archival profile gets
a TSA countersignature. The document timestamp (DTS) is itself a
TimeStampToken anchored to the TSA's RSA key.

### Debian `sbuild` / reproducible-build
`debsign --tsa-url` for detached build-id timestamps.

### Software supply-chain provenance
- in-toto attestations consumed by Sigstore Rekor have their own
  inclusion-proof, but often carry a TSA countersignature for
  offline verifiability.
- GNU Guix / Nix build metadata archives ship with TSA signatures
  on build manifests.
- SLSA provenance attestations (see `sigstore-model-signing/`) may
  include a TSA countersignature on the statement digest.

### Archival systems
- Electronic invoicing (ZUGFeRD, FatturaPA, Peppol BIS) often
  timestamps the invoice XML.
- Electronic land-registry, notarial, and court filings in Germany,
  France, Italy, Spain, Portugal all archive TSA-countersigned
  documents under eIDAS LTV requirements.

## Client code (schematic usage of `tsa_rfc3161.py`)

    from tsa_rfc3161 import request_timestamp, verify_timestamp_chain

    token = request_timestamp(
        tsa_url="http://timestamp.digicert.com",
        data_digest=sha256(data),
        digest_algo="sha256",
        cert_req=True,
    )
    verify_timestamp_chain(
        token, data_digest=sha256(data),
        trust_roots=[open("digicert-root.pem", "rb").read()],
    )

## Breakage

A TSA's RSA signing key is *the* archival-longevity anchor for every
document ever timestamped by that TSA. A factoring attack lets an
attacker:

- Retroactively re-timestamp any document at any historical date the
  TSA covers. A forged contract "signed and timestamped 2018-06-14"
  becomes as credible as a genuine one to every PAdES / Acrobat /
  court archival system that treats TSA signatures as authoritative.
- Validate expired / revoked code-signing certs indefinitely —
  Authenticode treats a TSA signature at the moment of signing as
  authoritative, and if the TSA's key is forgeable, the entire
  "signature was valid at signing time" guarantee collapses across
  Windows software signed over the last 20 years.
- Break Adobe's Long-Term Validation model: PAdES-LTA is defined as
  "signature + TSA token + revocation info at signing time", all
  of which are RSA signatures; a TSA break re-opens every LTV-
  archived PDF to re-forgery.

TSA key rotation happens every few years but the *existing*
timestamps remain valid forever under the original key. Unlike TLS,
there is no post-break recovery path short of a fresh
re-timestamping under a non-RSA TSA of every historically
consequential document — which is operationally infeasible at the
scale of 20 years of European court archives.
