# SAP NetWeaver SSO — where `sap_rsa_sso.java` is actually invoked

SAP SSO 3.0 + SAP Secure Login Client + SAP NetWeaver AS Java / AS
ABAP issue and consume X.509 logon tickets wrapping RSA-2048+
signatures. Deployed across every Global-2000 SAP shop: S/4HANA
Finance, SuccessFactors-on-prem, Ariba procurement, IBP supply
planning, BW/4HANA analytics, Solution Manager ops.

## Touchpoints

### SPNEGO + X.509 fallback logon to ABAP stacks
Workstation → SAP GUI → DIAG over secnet (SNC).  The SNC layer
handshakes with Kerberos first; where the user is offline or the KDC
is unreachable, SAP Secure Login Client presents an X.509 client cert
issued by the SAP PSE Server CA (RSA-2048).  `sap_rsa_sso.java`'s
`verifyLogonTicket` runs on the AS Java receiving side and validates
the ticket's XMLDSig / PKCS#7 signature.

### SAP Cloud Connector — principal propagation
An on-prem → BTP call via the Cloud Connector walks: Subscriber
XSUAA JWT (RS256 over RSA-2048) → Cloud Connector short-lived X.509
(RSA-2048) minted per request → on-prem ABAP accepts the cert and
maps it to a SU01 user via USREXTID.  All four of those are RSA
signatures feeding `sap_rsa_sso.java`.

### SAML2 browser SSO for Fiori
AS Java `sap.com/tc~sec~saml2~service` issues AuthnRequests to
corporate IdPs (Entra ID, Azure AD, Okta, SAP Identity Authentication
Service).  Returning SAMLResponses are XMLDSig-RSA-SHA256 signed;
`verifyAssertion` calls into `sap_rsa_sso.java`.

### SAP Passport (distributed trace)
Every end-to-end call in a SAP landscape carries an SAP Passport
header signed by the originating component's PSE.  Admin forensics
tooling checks the chain of signatures — RSA all the way through.

## Config glue (STRUST / NWA / profile params)

    # Relevant abap instance profile lines
    snc/enable = 1
    snc/gssapi_lib = /usr/sap/sapcrypto/libsapcrypto.so
    snc/identity/as = p:CN=s4hprod, OU=SAP, O=Corp, C=US
    icm/HTTPS/verify_client = 1        # require client cert on HTTPS
    login/certificate_mapping_rulebased = 1
    ume.login.mapping.policy_configuration = X509_CERT

    # STRUST PSE list that the node loads at startup:
    # - SAPSSLS.pse (TLS server cert, RSA-2048)
    # - SAPSSLC.pse (TLS client cert for outbound RFC-TLS)
    # - SAPSYS.pse  (system PSE: SAP Passport signer)
    # - SAML_SP.pse (SAML SP signer/encrypter)

## Breakage

A factoring attack against:

- **SAP Passport CA key**: attacker forges Passport signatures and
  replays cross-system calls that AS ABAP treats as authenticated
  bearer-of-role tokens.  Movement of funds, vendor-master changes,
  payroll edits — everything attributable to a "trusted" upstream
  component.
- **Cloud Connector / BTP subaccount signing key**: any SaaS-to-
  on-prem call can be forged as an arbitrary business user.  ABAP
  authorization kicks in only after identity is established, and
  Cloud Connector principal propagation is identity establishment.
- **SAP IAS / corporate IdP SAML signing key**: one forged
  SAMLResponse mints a Fiori session as any SAP_ALL holder, e.g.
  SAP* or DDIC.  From there, transaction SE38 / SE16N gets the
  attacker root-equivalent inside the S/4HANA database.

SAP PSEs are rotated with SAP STRUST + RSECADMIN; historical
Passports and SAML assertions remain verifiable under the old key
for the archival window (7 years for SOX-relevant audit logs), so
post-break forensic ambiguity is durable.
