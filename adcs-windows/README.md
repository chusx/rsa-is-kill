# adcs-windows — RSA-2048 defaults in Windows enterprise PKI

**Software:** Microsoft Active Directory Certificate Services (AD CS / ADCS) 
**Industry:** Enterprise IT, government, healthcare — any Windows Active Directory environment 
**Algorithm:** RSA-2048 (all built-in certificate templates and CA defaults) 

## What it does

Active Directory Certificate Services is the Windows enterprise certificate authority,
deployed in the majority of corporate and government Active Directory environments.
AD CS issues certificates to every domain computer, user, and service automatically
via autoenrollment.

AD CS is the PKI backbone for:
- **Domain computer certificates** — every domain-joined machine gets one via autoenrollment
- **PKINIT / Windows Hello for Business** — RSA-2048 smartcard logon certs (see kerberos-pkinit/)
- **EAP-TLS Wi-Fi** — device and user certs for 802.1X (see eap-tls-wifi/)
- **SSTP / IKEv2 VPN** — client certificates for DirectAccess and Always On VPN
- **Code signing** — internal code signing CA for PowerShell and application packages
- **S/MIME** — user email signing certificates (see smime-email/)
- **OCSP / CRL signing** — certificate status responses signed with RSA

Every built-in ADCS certificate template has `msPKI-Minimal-Key-Size: 2048` with
`pKIPublicKeyAlgorithm: 1.2.840.113549.1.1.1` (rsaEncryption). The CNG KSP
(Key Storage Provider) defaults to RSA. There is no ML-DSA KSP available.

The CA certificate itself (the root/enterprise CA) is RSA-2048 with a 20-year default
validity. Everything issued under it chains to the RSA root.

## Why it's stuck

- The Windows CNG (Cryptography Next Generation) API has no ML-DSA or ML-KEM provider.
 No CNG algorithm ID is defined for any NIST non-RSA algorithm (as of Windows Server 2025)
- AD CS certificate templates are stored in Active Directory and replicated across
 the forest. There is no non-RSA template type in the schema
- Certificate autoenrollment (Group Policy) has no mechanism to request non-RSA key types
- Microsoft has not announced a timeline or roadmap for non-RSA support in AD CS
- Enterprise deployments have hundreds or thousands of certificate-dependent applications.
 Algorithm migration would require testing every dependent system

## impact

AD CS is the PKI for the entire Windows domain. the root CA RSA key is the root of
trust for everything the domain issues. it's in the config partition of Active Directory,
readable by any authenticated user.

- the AD CS root CA certificate is published in the AIA extension of every issued
 certificate, in LDAP at CN=Configuration, and is synced to every Windows client's
 trusted root store. RSA-2048 public key, publicly readable, input for the attack ready
- factor the root CA RSA key and issue certificates for any domain user, computer,
 or service. issue a certificate for any domain admin, do PKINIT, get a TGT, own
 the domain. no password, no phishing, no exploitation of any software vulnerability
- every ADCS-issued certificate is on the table: Wi-Fi certs, VPN certs, code signing
 certs, S/MIME certs. one root key compromise cascades through the entire PKI hierarchy
- typical Fortune 500 deployment: 50,000-500,000 issued certificates all chaining
 to the compromised RSA-2048 root

## Code

`adcs_rsa_default.ps1` — `Install-AdcsCertificationAuthority` with `KeyLength 2048`
(RSA-2048 default), certificate template inspection showing `msPKI-Minimal-Key-Size: 2048`
and `pKIPublicKeyAlgorithm: rsaEncryption`, and notes on the full enterprise
attack chain (factor root -> issue cert -> PKINIT -> TGT -> domain admin).
