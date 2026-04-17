# XMLDSig via xmlsec1 — where `xmlsec1_rsa.c` lands in production

xmlsec1 / libxmlsec is the reference C implementation of the
W3C XMLDSig and XMLEnc specifications.  Its RSA primitive path
(`xmlsec1_rsa.c`) is invoked on every sign/verify by a wide
set of downstream consumers:

## Identity / federation
- **SAML 2.0** — every Shibboleth SP, SimpleSAMLphp IdP, Microsoft
  AD FS (via its own ACS), Keycloak, Okta, PingFederate, Entra ID
  on-prem SAML issuance, and the Ruby / PHP / Python / Java SAML
  libraries all sign AuthnRequests, Responses, LogoutRequests
  with XMLDSig-RSA-SHA256.  See `saml-ruby/`.
- **WS-Federation / WS-Trust / WS-SecurityPolicy** — legacy but
  still deployed across banking (SWIFT GPI portals), Microsoft
  Sharepoint on-prem claims authentication, BizTalk Server B2B
  adapters.
- **SOAP WS-Security** — every XML Signature in a `<wsse:Security>`
  header goes through an XMLDSig library with an RSA primitive
  underneath.

## E-invoicing / tax
- **FatturaPA (Italy)** — mandatory XMLDSig on every electronic
  invoice sent through SdI (Sistema di Interscambio). RSA-2048
  certs issued by Agenzia delle Entrate-trusted CAs.
- **Peppol BIS / UBL** — Peppol Access Points sign every document
  in transit with XMLDSig.  PEPPOL Authority-issued certs chain
  to the OpenPEPPOL root.
- **ZUGFeRD / XRechnung (Germany)**, **Chorus Pro (France)**,
  **SAT CFDI (Mexico)**, **SRI (Ecuador)**, **DIAN (Colombia)**,
  **SII (Chile)** — every LATAM + EU tax authority that issues
  XML e-invoices uses XMLDSig-RSA over the invoice document,
  signed by the taxpayer's CA-issued key, verified by the tax
  authority's submission endpoint.

## Court filings + archival
- **German court e-filing (beA, EGVP)** — mandatory XMLDSig-RSA
  on every electronic filing by German attorneys.
- **French Chorus Pro** (public-sector invoicing) — as above.
- **Spanish @firma platform** — national digital-signature
  framework underpinning every XMLDSig sign/verify for public
  administration.

## eIDAS QES / AdES profiles
- **XAdES** (W3C + ETSI TS 101 903) — the XML dialect of the
  European Advanced Electronic Signature standard. QES-level
  XAdES signatures are legally equivalent to handwritten
  signatures across all 27 EU member states.
- **XAdES-B-LTA** — long-term-archival XAdES with embedded
  timestamps (see `rfc3161-tsa-timestamp/`) and revocation
  info, archivable for 30+ years under the Qualified TSP regime.

## DNSSEC zone-signing helpers (some implementations)
- While BIND9 and PowerDNS have their own RSA primitives, some
  DS-over-XML publication tooling uses xmlsec1.

## Configuration-management / policy
- **SAP XI / PI / PO** SOAP adapters sign outbound WS-Security
  envelopes with XMLDSig-RSA using STRUST PSEs (see
  `sap-netweaver-sso/`).
- **MuleSoft, TIBCO BusinessWorks, IBM DataPower** — XML gateways
  enforcing XMLDSig verify on every inbound message.
- **OASIS Ebiquity / ebXML** — cross-organizational B2B message
  exchange, every envelope XMLDSig-RSA signed.

## CLI invocation (what integrators actually run)

    # Sign (XMLSec reference CLI — these are what gets scripted in
    # Jenkins / GitHub Actions pipelines for tax-filing consumers)
    xmlsec1 --sign --privkey-pem taxpayer.key,taxpayer.crt \
        --output invoice-signed.xml invoice-template.xml

    # Verify — at receiving endpoint (SdI / Peppol AP / court EGVP)
    xmlsec1 --verify --trusted-pem agenzia-entrate-root.crt \
        invoice-signed.xml

Both operations land in `xmlsec1_rsa.c::xmlSecOpenSSLRsaSha256Execute`.

## Breakage

A factoring attack against:

- **A national tax-authority root CA** (Agenzia delle Entrate,
  AEAT, SAT, SII, DIAN): attacker mints taxpayer certs and issues
  fraudulent invoices accepted by the authority's submission
  endpoint. Tax-refund fraud at national scale — Italy alone
  processes >2 billion XMLDSig-RSA-signed invoices/year.
- **An eIDAS QTSP root** (Camerfirma, SwissSign, D-Trust, Actalis,
  ANF): attacker issues QES-equivalent certificates and signs
  contracts, notarial documents, court filings with the force of
  handwritten signatures under Regulation (EU) No 910/2014.
  Unwinding retroactively is a political-legal problem, not a
  technical one.
- **A Peppol Authority root CA**: attacker injects forged POs,
  invoices, shipping notices into Peppol AP traffic; cross-border
  B2B commerce across ~40 member economies is spoofable.
- **A SAML IdP signing key** (per-tenant): see `saml-ruby/`.

XMLDSig-RSA archives at European courts and tax authorities are
retention-bound for 10–30 years, so a factoring break opens
every historical filing to re-forgery.
