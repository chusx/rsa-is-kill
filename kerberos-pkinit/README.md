# Kerberos PKINIT — RSA Certificate Authentication for Active Directory

**Source:** https://github.com/krb5/krb5 
**File:** `src/plugins/preauth/pkinit/pkinit_crypto_openssl.c` 
**Reference:** RFC 4556 (PKINIT), MS-PKCA (Microsoft extension) 
**License:** MIT

## what it does

PKINIT allows X.509 certificates (from smart cards, TPMs, Windows Hello for Business) to authenticate to Kerberos KDCs. It's the foundation of certificate-based enterprise SSO. The client signs an authentication request with their RSA private key; the KDC verifies it against the enterprise PKI.

## impact

PKINIT is how smart cards and Windows Hello log into Active Directory. the client cert, the KDC cert, the CA cert are all RSA and they're all readable from LDAP by any domain user.

- every enterprise PKI issues RSA certs stored in the AD userCertificate attribute, readable by anyone on the domain. the input an attacker needs has been publicly available the entire time
- forge a user's PKINIT RSA signature, get their Kerberos TGT without their password or smart card, then access every Kerberized service: SMB, Exchange, SharePoint, SQL Server, everything
- Windows Hello for Business uses TPM-backed RSA keys. DC-to-DC authentication uses PKINIT. Azure AD hybrid join uses PKINIT. this is a full AD domain compromise using only a public certificate
- no non-RSA PKINIT RFC exists. KDCs have no non-RSA certificate validation path. Microsoft hasn't announced a timeline for any of this
