# saml-ruby — RSA-SHA256 in enterprise SSO

**Software:** ruby-saml (SAML-Toolkits/ruby-saml)  
**Industry:** Enterprise identity, SSO, HR/ERP systems (Okta, Azure AD, Salesforce, GitHub)  
**Algorithm:** RSA-SHA1 (default), RSA-SHA256/384/512  
**PQC migration plan:** None — W3C XMLDSig specification has no PQC algorithm URIs

## What it does

ruby-saml is the canonical Ruby implementation of SAML 2.0 authentication,
used by Okta, Azure AD, GitHub, GitLab, Salesforce, and virtually every
Ruby-based enterprise application that participates in SSO.

SAML 2.0 assertions (which convey user identity and authorization) are signed
with XML Digital Signatures (XMLDSig). The XMLDSig spec defines exactly four
signature algorithms — all RSA:

```
RSA_SHA1   = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
RSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
```

The default in ruby-saml is `RSA_SHA1`. There is no DSA, ECDSA, or PQC
option in XMLDSig — the spec is RSA-only by design.

## Why it's stuck

- The W3C XMLDSig specification is the normative reference; adding a PQC URI
  requires a new W3C spec process
- SAML IdPs (Okta, Azure AD, etc.) and SPs must agree on the same algorithm
- Billions of SAML assertions are processed daily; a flag day is not possible
- Enterprise identity systems are deeply integrated and change-averse

A CRQC can forge arbitrary SAML assertions, gaining identity as any user at
any service provider that trusts the compromised IdP certificate.

## Code

`xml_security_rsa.rb` — `sign_document()` and `compute_signature()` showing
all four RSA algorithm constants and RSA-only signing path.
