# xmlsec1-xmldsig — RSA in XML Digital Signatures (SAML, eGov, X-Road)

**Repository:** lsh123/xmlsec (also aleksey.com/xmlsec/) 
**Industry:** Electronic government, SAML SSO, EU eIDAS, Estonian X-Road 
**Algorithm:** RSA-SHA256 / RSA-SHA1 — W3C XMLDSig algorithm URIs 

## What it does

xmlsec1 is the C implementation of W3C XML Digital Signatures. It is the signature
engine behind a large fraction of SAML SSO infrastructure and electronic government:

- **mod_auth_mellon** — the Apache HTTPD SAML service provider module, used by
 thousands of universities and government agencies for SSO
- **SimpleSAMLphp** — the most-deployed PHP SAML library, used by virtually every
 university and many government identity providers
- **lasso** — C/Python/Perl SAML library; used in enterprise and government SSO
- **Estonian X-Road** — the inter-agency data exchange backbone for Estonian
 e-government. Over 1000 organizations sign every SOAP message with XMLDSig.
 Health records, tax data, business register, police databases, courts — all X-Road
- **Belgian eID** — the Belgian federal electronic identity card infrastructure uses xmlsec1
- **PEPPOL** (Pan-European Public Procurement OnLine) — EU-wide electronic procurement;
 all documents signed with XMLDSig

The W3C XMLDSig namespace (`http://www.w3.org/2001/04/xmldsig-more#`) was last extended
in 2013. No ML-DSA algorithm URI has been proposed. There is no active W3C XML Security
Working Group (it closed in 2013). Without a registered URI, any non-RSA XMLDSig signature
would fail to parse in every conformant XMLDSig implementation.

## Why it's stuck

- The W3C XML Digital Signature algorithm URI namespace is effectively frozen.
 No new algorithms can be added without a new W3C recommendation, which requires
 a new working group, drafts, review cycles — typically 3-5 years
- Estonian X-Road security server specifications mandate specific XMLDSig algorithm
 URIs. A unilateral URI change by one party would break interoperability with all
 other X-Road participants. X-Road is a federated system; everyone must update simultaneously
- SAML specifications (SAML 2.0, 2005) reference specific XMLDSig algorithm URIs.
 The OASIS SAML TC would need to update the spec and every SAML implementation
 would need simultaneous updates to accept new non-RSA signature algorithm URIs
- SimpleSAMLphp and mod_auth_mellon use xmlsec1 as a library. If xmlsec1 doesn't
 support a non-RSA algorithm, nothing using xmlsec1 can either

## impact

SAML SSO and eGovernment XMLDSig are the authentication layer for a lot of important
things. X-Road in particular is remarkable — it's an entire government's data
infrastructure sitting on RSA XMLDSig.

- forge a SAML assertion signed with xmlsec1. mod_auth_mellon accepts it and grants
 access to any protected resource at any Apache-based SP. this is the same attack
 as saml-ruby/ but in C, affecting a different deployment base
- Estonia's X-Road: forge an XMLDSig signature on a SOAP request. inject false tax
 authority data, modify health records, create fraudulent business registrations.
 X-Road signatures are the legal attestation for government data exchange. the entire
 Estonian digital government runs on this
- PEPPOL electronic procurement: forge digital signatures on procurement documents.
 create fraudulent bids or purchase orders that pass signature verification across
 the EU public procurement system
- Belgian eID: forge signatures on legally-binding electronic documents. eIDAS
 qualified electronic signatures on RSA XMLDSig have the same legal standing as
 a handwritten signature in every EU member state. the legal validity collapses

## Code

`xmlsec1_rsa.c` — `xmlSecOpenSSLTransformRsaSha256Id` (RSA-SHA256 transform),
`xmlSecOpenSSLRsaSign()` (EVP_DigestSign with RSA PKCS#1 v1.5 over canonicalized
SignedInfo), and `xroad_sign_message()` showing Estonian X-Road SOAP message signing
with `xmlSecDSigCtxSign()`. From `src/openssl/signatures.c`.
