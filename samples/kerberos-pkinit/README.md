# Kerberos PKINIT — RSA Certificate Authentication for Active Directory

**Source:** https://github.com/krb5/krb5  
**File:** `src/plugins/preauth/pkinit/pkinit_crypto_openssl.c`  
**Reference:** RFC 4556 (PKINIT), MS-PKCA (Microsoft extension)  
**License:** MIT

## what it does

PKINIT allows X.509 certificates (from smart cards, TPMs, Windows Hello for Business) to authenticate to Kerberos KDCs. It's the foundation of certificate-based enterprise SSO. The client signs an authentication request with their RSA private key; the KDC verifies it against the enterprise PKI.

## why it's a full domain compromise vector

- Every enterprise PKI issues RSA certificates. The client cert, the KDC cert, the CA cert — all RSA.
- Certificates are public: they're in Active Directory's LDAP (`userCertificate` attribute), readable by any domain user.
- Forge a user's PKINIT RSA signature → get their Kerberos TGT without their password or smart card.
- With a TGT, access every Kerberized service: SMB shares, Exchange, SharePoint, SQL Server, custom apps.
- This is a **full AD domain compromise** requiring only the user's public certificate (public!) and a CRQC.
- PKINIT is also used for Windows Hello for Business (hardware-protected RSA keys in TPMs), DC-to-DC authentication, and Azure AD hybrid join.
- No PQC PKINIT RFC exists. The IETF hasn't published one. KDCs have no PQC certificate validation path.

## migration status

No PQC PKINIT standard. Microsoft has not announced a timeline. Windows Hello for Business and AD CS (Certificate Services) are entirely RSA/ECDSA.
