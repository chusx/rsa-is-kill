# apache-santuario — RSA in XML Digital Signatures (WS-Security, SAML, HL7)

**Repository:** Apache SVN — `svn.apache.org/repos/asf/santuario/xml-security-java/`  
**Industry:** Enterprise Java, healthcare (HL7), government SOAP, financial SOAP APIs  
**Algorithm:** RSA-SHA256 / RSA-SHA1 — W3C XMLDSig algorithm URIs  
**PQC migration plan:** None — W3C XML Digital Signature spec has no ML-DSA URI; no W3C working group item for PQC XMLDSig

## What it does

Apache Santuario is the Java implementation of W3C XML Digital Signatures (XMLDSig)
and XML Encryption. It is the underlying crypto layer for virtually every enterprise
SOAP stack on the JVM:

- **Apache WSS4J** — WS-Security for SOAP messages; used by every JAX-WS service
- **Apache CXF** — the dominant Java web services framework; used in healthcare, finance, government
- **Spring-WS** — Spring Framework SOAP; used in countless enterprise applications
- **Shibboleth IdP** — the SAML identity provider used by ~10,000 universities worldwide
- **HL7 v3 SOAP messaging** — hospital EHR interoperability (Epic, Cerner, Allscripts)
- **ISO 20022 SOAP APIs** — banking payment messages over SOAP (many smaller institutions)
- **US federal e-Government SOAP** — agency-to-agency XML data exchange

The W3C XMLDSig algorithm URIs for RSA are registered. For ML-DSA: nothing is registered.
The W3C XML Security Working Group closed in 2013. There is no active W3C body working
on PQC XMLDSig. The existing URI namespace (`http://www.w3.org/2001/04/xmldsig-more#`)
has not been extended with any PQC algorithm since it was published.

## Why it's stuck

- The W3C XMLDSig specification defines the algorithm URI namespace. No new PQC URI
  has been registered or proposed. Until it is, any PQC XMLDSig signature would be
  non-standard and rejected by conformant validators
- HL7 v3 and ISO 20022 SOAP profiles explicitly require RSA-SHA256 or RSA-SHA1 algorithm
  URIs in their message signing specs. Healthcare and financial messaging specs update
  on decade-long timescales
- WS-Policy files in deployed SOAP services hardcode `<sp:AlgorithmSuite><sp:Basic256Sha256>`
  which maps to RSA-SHA256. Changing the algorithm requires WS-Policy renegotiation
  across all service partners
- Shibboleth IdP and every SAML implementation using Apache Santuario would need
  simultaneous updates with the tens of thousands of SP (service provider) federations
  they serve

## impact

XMLDSig is the signature format for enterprise SOAP services, healthcare interoperability,
and SAML. every RSA-signed SOAP message or SAML assertion in these stacks is forgeable.

- forge a WS-Security signed SOAP message appearing to come from any SOAP client or
  service with a known certificate. in a banking SOAP API, that's a payment instruction
  signed by any bank's RSA private key. same impact as swift-financial but hitting the
  SOAP layer instead of the SWIFT network itself
- HL7 v3 uses WS-Security SOAP for hospital-to-hospital patient data exchange. forge
  a signed HL7 message, inject false patient records or false lab results into receiving
  EHR systems. the RSA signature is the authenticity guarantee
- Shibboleth IdP signs SAML assertions with RSA. Shibboleth serves ~10,000 universities
  in the eduroam/InCommon federation. forge a SAML assertion from any university IdP and
  log in as any student, staff, or administrator at any university that trusts that federation
- SOAP e-Government services in the US, EU, and Australia use RSA XMLDSig for
  legally-binding agency data exchange. forged signatures undermine the legal validity
  of the entire XML-based inter-agency communication framework

## Code

`xmlsec_rsa_sign.java` — `XMLSignature.sign()` (RSA PKCS#1 v1.5 over canonicalized
SignedInfo), `XMLSignature.checkSignatureValue()` (RSA verification), all RSA algorithm
URI constants, and `WSSecSignature.build()` showing WS-Security SOAP signing in WSS4J.
From `santuario-java` on `svn.apache.org`.
