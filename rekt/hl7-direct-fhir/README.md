# HL7 DIRECT Project + FHIR — signed health information exchange

**DIRECT** (formerly the NwHIN Direct Project) is the US federal
**ONC**-promoted standard for secure clinical messaging between
healthcare providers. It's an S/MIME-over-SMTP profile: a DIRECT
address looks like `jane.doe@direct.hospital.org`, and every
message is RSA-signed + RSA-encrypted under certificates chained
to **DirectTrust**-accredited CAs.

**HL7 FHIR** is the ubiquitous modern healthcare API (R4, R5, R6
in draft). The **SMART on FHIR** authorization profile + **UDAP**
(Unified Data Access Profile) mandate asymmetric-key authentication
for app registration and access — RS256 JWT client assertions over
RSA keypairs.

## Consumer footprint

- **DIRECT** is the backbone for US inter-provider referrals: every
  EHR (Epic, Cerner/Oracle Health, Meditech, Allscripts/Veradigm,
  NextGen, athenahealth) ships a DIRECT client. Estimated 100M+
  messages/year.
- **DirectTrust** network: ~1.9 million addresses, every major
  health-system + independent practice.
- **FHIR R4**: required by 21st Century Cures Act for all certified
  EHR technology (post-2023 enforcement). Every patient-data API
  call through USCDI-conformant endpoints rides this.
- **CARIN Blue Button** (Medicare), **Da Vinci Project** (payer-
  provider exchange), **TEFCA QHINs** (Qualified Health Information
  Networks) all rely on RSA-rooted PKI.

## RSA touchpoints

### 1. DIRECT S/MIME certificates
Issued by DirectTrust-accredited CAs (DigiCert Healthcare,
IdenTrust, InCommon, Entrust). RSA-2048+ leaf certs. Every DIRECT
message is RSA-signed + encrypted to recipient's RSA pubkey —
including clinical-document attachments (CDA, CCDA, lab results,
imaging reports).

### 2. SMART on FHIR client-authentication JWT
Under the SMART-on-FHIR Backend Services spec (and UDAP Dynamic
Client Registration), applications (pharmacy systems, claims
clearinghouses, patient apps) register public RSA keys with the
EHR authorization server. App-to-EHR auth at token-endpoint uses
an RS256-signed JWT client assertion.

### 3. TEFCA / Qualified Health Information Networks
RCE-accredited QHINs (eHealth Exchange, CommonWell, Carequality,
Epic Care Everywhere, Kno2) cross-connect via the TEFCA Common
Agreement with mutual TLS + RSA client certs.

### 4. IHE XDS / XCA / XDR cross-enterprise document sharing
International Healthcare Enterprise (IHE) Cross-Enterprise
Document Sharing profiles still anchor on XMLDSig-RSA for document
integrity and non-repudiation across EU national health systems
(Germany TI, France INS/Ségur, Estonia X-Road, Denmark MedCom).

### 5. FDA Sentinel / PCORnet research queries
Federated research queries to DataMart partners are signed for
audit trail — RSA-2048 mutual cert auth.

## Breakage

A factoring attack against:

- **A DirectTrust accredited CA**: attacker mints a DIRECT cert for
  `attacker@direct.hospital.org`, sends forged referrals + clinical
  orders that receiving EHRs accept as authenticated physician
  communication. Triggers medication changes, admission orders,
  forged lab-result distributions under the authority of the
  impersonated clinician.
- **A SMART-on-FHIR app JWT key** (individual app): attacker
  authenticates as a legitimate app against every EHR the app is
  registered with, exfiltrating patient data or writing forged
  clinical documents. Under 21C Cures information-blocking rules,
  EHRs cannot easily rate-limit without penalty.
- **A QHIN signing CA**: cross-HIE impersonation; pull patient
  records from any participating health system by presenting
  forged QHIN credentials.
- **An EHR's own issuing CA for internal certificates** (Epic
  Hyperspace, Cerner PowerChart internal RSA keys): attacker
  decrypts captured clinical-messaging traffic, forges audit-log
  signatures hiding unauthorized chart access (HIPAA violation
  attribution gaps).

Healthcare PKI rotation is notoriously slow — DirectTrust cert
validity is typically 3 years, and re-enrollment across thousands
of practices takes a year-plus. A factoring break has cleanup
timescales measured in years, during which clinical
confidentiality and integrity are in a cryptographic grey zone.
