# adcs_rsa_default.ps1
#
# Microsoft Active Directory Certificate Services (AD CS) — RSA-2048 defaults.
# AD CS is the Windows enterprise CA, deployed in the majority of
# corporate Active Directory environments.
#
# Reference: Microsoft ADCS documentation, certutil, PSPKI module
# GitHub: PKISolutions/PSPKI — https://github.com/PKISolutions/PSPKI
#         (PowerShell PKI module for AD CS administration)
#
# AD CS is the PKI infrastructure for:
#   - Domain computers (Machine certificates, autoenrollment)
#   - Domain users (User certificates, smartcard logon = PKINIT)
#   - Web servers (IIS certificates via web enrollment)
#   - 802.1X EAP-TLS (device and user certs for Wi-Fi/NAC)
#   - VPN (SSTP, IKEv2, DirectAccess — all use RSA-2048 client certs)
#   - Code signing (internal code signing CA)
#   - Email (S/MIME certs for Outlook)
#   - BitLocker (key recovery agent certificates)
#
# The default CA configuration and ALL built-in certificate templates
# use RSA-2048. There is no ADCS template for ML-DSA or ML-KEM.
# Windows Server 2025 has no PQC algorithm support in ADCS.
# The CNG (Cryptography Next Generation) API has no ML-DSA provider.


# ============================================================
# AD CS Root CA installation with default RSA-2048 settings
# ============================================================

# Install the AD CS role
Install-WindowsFeature -Name AD-Certificate -IncludeManagementTools

# Install a Standalone Root CA — RSA-2048 is the default
# Source: PSPKI module Install-CertificationAuthority wrapper
Install-AdcsCertificationAuthority `
    -CAType StandaloneRootCA `
    -CACommonName "Contoso Root CA" `
    -KeyLength 2048 `               # RSA-2048 — the hardcoded default in the wizard
    -HashAlgorithmName SHA256 `     # SHA256WithRSAEncryption
    -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" `
    -ValidityPeriod Years `
    -ValidityPeriodUnits 20 `       # 20-year root CA validity
    -Force

# The resulting CA certificate:
#   Subject: CN=Contoso Root CA
#   Public Key: RSA (2048 bits)
#   Signature Algorithm: sha256WithRSAEncryption
#   Validity: 20 years (expires 2044 if installed today)


# ============================================================
# Built-in ADCS Certificate Templates — all RSA-2048
# ============================================================

# Every built-in template uses RSA-2048 as the default.
# These templates are replicated to all ADCS servers in the forest via AD.

# Example: Computer template (machine authentication)
$template = Get-CertificateTemplate -Name "Computer"
# Template properties:
#   msPKI-Private-Key-Flag: 0x01000000 (ATTEST_PREFERRED)
#   msPKI-Minimal-Key-Size: 2048       <-- RSA-2048 minimum
#   pKIDefaultKeySpec: AT_KEYEXCHANGE  (RSA key exchange)
#   pKIPublicKeyAlgorithm: 1.2.840.113549.1.1.1  (rsaEncryption OID)

# Example: Smartcard Logon template (PKINIT client certs for Windows Hello for Business)
$whfbTemplate = Get-CertificateTemplate -Name "SmartcardLogon"
# msPKI-Minimal-Key-Size: 2048 (RSA-2048)
# This is the template used for Windows Hello for Business hardware-backed keys
# when deployed in certificate trust mode (not the newer cloud trust mode)


# ============================================================
# ADCS autoenrollment — RSA-2048 certs issued to every domain computer
# ============================================================

# Group Policy configures autoenrollment for Computer and User templates.
# Every domain-joined computer automatically requests a certificate.
# In an enterprise with 100,000 computers, that's 100,000 RSA-2048 certs.

# Trigger autoenrollment on a client
certutil -pulse  # or: CertMgmt -> Certificates -> All Tasks -> Automatically Enroll

# The machine's RSA-2048 private key is stored in the machine's TPM (if TPM-backed)
# or in the software key store (%ProgramData%\Microsoft\Crypto\RSA)
# The public key is in the certificate, stored in Active Directory (AD)
# under the computer object's userCertificate attribute (readable by all AD users)


# ============================================================
# PSPKI: examining CA and template RSA parameters
# Source: PKISolutions/PSPKI Get-CertificationAuthority
# ============================================================

Import-Module PSPKI

# List all CAs in the forest with their key algorithm
Get-CertificationAuthority | Select-Object ComputerName, DisplayName, @{
    Name="KeyAlgorithm"
    Expression={ ($_ | Get-CAExchangeCertificate).PublicKey.Oid.FriendlyName }
}
# Output: all CAs show "RSA" with 2048-bit keys
# No CA in a default Windows environment shows "ML-DSA" or any PQC algorithm

# Check a CA's signing algorithm
$ca = Get-CertificationAuthority -ComputerName "dc01.contoso.com"
$ca.Certificate.SignatureAlgorithm
# { FriendlyName = "sha256RSA", Value = "1.2.840.113549.1.1.11" }
# sha256WithRSAEncryption — the CA signs every issued certificate with its RSA key


# ============================================================
# CRQC attack scenario for AD CS:
#
# 1. Factor the Enterprise Root CA RSA-2048 key.
#    The CA certificate (with public key) is published in:
#    - Active Directory: CN=Configuration,DC=contoso,DC=com
#      (readable by any domain user or any authenticated machine)
#    - AIA extension of every issued certificate
#    - HTTP/LDAP CDP and AIA URLs (public in every cert)
#
# 2. With the CA private key:
#    - Issue certificates for any user or computer in the domain
#    - Issue a certificate for any domain admin account
#    - Use PKINIT with the forged cert to get a Kerberos TGT for any user
#    - Issue code signing certificates accepted by any internal code signing policy
#    - Issue S/MIME certificates for any user's email address
#
# 3. Scale: a single enterprise AD CS Root CA covers the entire company.
#    Typical Fortune 500 deployments: 50,000-500,000 issued certificates,
#    all chaining to the compromised RSA-2048 root.
#
# There is no PQC algorithm supported by Windows ADCS (Server 2025).
# Microsoft has not published a ADCS PQC migration plan or timeline.
# ============================================================
