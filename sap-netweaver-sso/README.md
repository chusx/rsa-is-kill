# sap-netweaver-sso — RSA in SAP NetWeaver SSO (77% of global transaction revenue)

**Repository:** SAP NetWeaver (proprietary); SAP Note 2028703; SAP NetWeaver SSO 2.0 Admin Guide  
**Industry:** Enterprise ERP — SAP runs financial, HR, and supply chain for most of the Fortune 500  
**Algorithm:** RSA-2048 (SAP Logon Ticket signing, X.509 client cert SSO, SAP HANA TLS, Web Dispatcher cert)  
**PQC migration plan:** None — SAP NetWeaver has not published any PQC roadmap; STRUST (SAP certificate management) has no PQC key type; SAP HANA TLS uses OpenSSL with no PQC stable release

## What it does

SAP NetWeaver is the runtime platform for SAP ERP, SAP S/4HANA, and every other ABAP/Java-based
SAP product. SAP processes an estimated 77% of global transaction revenue — every time a major
manufacturer buys parts, invoices a customer, or runs payroll, there's a decent chance it goes
through SAP.

RSA shows up in several critical SAP authentication paths:
- **SAP Logon Tickets**: RSA-2048 signed cookies (MYSAPSSO2) that let users SSO across the
  SAP landscape without re-authenticating. The issuing SAP system signs the ticket; accepting
  systems verify the RSA signature using the issuer's public key from STRUST (transaction).
- **X.509 client cert SSO**: Smart card, PKI, or SAP Identity Management certificates (RSA-2048)
  mapped to SAP users. TLS client cert auth to SAP ICM terminates at the Web Dispatcher or
  ABAP/Java application server.
- **SAP HANA TLS**: Database connections from SAP application servers to HANA use TLS with
  RSA-2048 server certificates from the SAP Landscape Management CA.
- **SAP Web Dispatcher**: Reverse proxy TLS termination with RSA-2048, front of every
  HTTP/HTTPS-facing SAP system.

## Why it's stuck

- SAP's cryptographic framework (the SAP Cryptographic Library, built on CommonCryptoLib)
  wraps OpenSSL. PQC in OpenSSL stable = PQC in SAP.
- STRUST (SAP certificate management transaction) manages RSA X.509 certificates for the
  entire SAP landscape. Adding PQC certificates requires SAP to update STRUST, the Java
  keystore handling, and the SSO ticket format simultaneously.
- SAP landscapes are conservatively maintained. SAP customers run specific patch levels and
  certify their ABAP custom code. Adding PQC to the SAP Cryptographic Library requires all
  SAP instances in the landscape to update at the same time, across what are often complex,
  multi-system SAP environments.
- SAP Logon Ticket format changes require updating every system in the landscape that issues
  or accepts tickets — the issuing system and all accepting systems need to support the new
  algorithm simultaneously.

## impact

SAP processes financial transactions, payroll, and procurement for most of the Fortune 500.
the RSA signature on the SAP Logon Ticket is the authentication layer for all of that.

- factor the issuing SAP system's RSA-2048 public key (it's in STRUST, exported as a PEM
  or DER cert during standard SAP trust configuration, often distributed to partners/integrations).
  derive the private key. forge MYSAPSSO2 tickets for any SAP user — including SAP_BASIS
  (the SAP equivalent of root) and the technical users that run ABAP batch jobs.
- SAP_BASIS access means: run any ABAP program, modify any configuration, access any table.
  the SAP financial data (FI/CO general ledger, accounts payable, bank accounts) and HR data
  (salaries, social security numbers, employment records) are fully accessible.
- for companies where SAP is the system of record for financial close: forge or delete journal
  entries, modify approved invoice records, change vendor bank accounts (classic Business Email
  Compromise but at the database level). the digital signature on the SAP document approvals
  is RSA-signed — forging the signing key means forging the approvals.
- SAP HANA MitM: factor the HANA server RSA-2048 cert. intercept SAP application server to
  HANA database connections. modify query results — make the balance sheet say what you want.
  inject false data into financial reports. this is inside the "trusted" network segment
  where nobody expects MitM.
- German federal government runs SAP (Bundesverwaltung). DoD contracts include SAP deployments.
  the same RSA SSO mechanism authenticates to government financial and HR systems.

## Code

`sap_rsa_sso.java` — `generateSapLogonTicket()` (RSA-2048 PKCS#1 v1.5 SHA-256 signed
MYSAPSSO2 ticket), `verifySapLogonTicket()` (Signature.getInstance("SHA256withRSA") verify),
`extractUserFromSapClientCert()` (X.509 CN -> SAP user ID mapping), `connectHanaWithTls()`
(HANA JDBC TLS with RSA-2048 truststore). SAP landscape scale and financial integrity context.
