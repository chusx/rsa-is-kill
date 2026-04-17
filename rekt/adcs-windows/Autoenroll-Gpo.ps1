# Autoenroll-Gpo.ps1
#
# Windows domain auto-enrollment policy + client-side enrollment flow.
# This is the real-world GPO + template layer around ADCS — the AD
# Certificate Services CA itself is the RSA issuer (see adcs_ca.cs);
# this script shows how every domain-joined Windows workstation gets
# an RSA-2048 client authentication cert automatically.

# --- GPO side: enforce auto-enroll on every DC-joined machine ----------
Set-GPRegistryValue -Name "Default Domain Policy" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment" `
    -ValueName "AEPolicy" -Type DWord -Value 7
# bits: 0x01 = enabled, 0x02 = renew expiring, 0x04 = update pending
# certs. 0x07 = all three, the standard enterprise setting.

# --- Certificate Template: "WorkstationAuthentication" -----------------
# Set by the domain PKI team; every template pins algorithm, key size,
# and (optionally) TPM attestation. These settings determine the RSA
# size of every auto-enrolled cert in the forest.
$template = @{
    Name                     = "WorkstationAuthentication"
    SchemaVersion            = 4
    CryptographyProvider     = "Microsoft Platform Crypto Provider"  # TPM-backed
    KeyAlgorithm             = "RSA"
    MinimumKeySize           = 2048
    SignatureAlgorithm       = "RSASSA-PSS with SHA-256"
    HashAlgorithm            = "SHA256"
    KeyAttestation           = "Required"       # must attest TPM origin
    PrivateKeyExportable     = $false
    ApplicationPolicies      = @("Client Authentication", "Smart Card Logon")
    EnrollmentPermissions    = @("Domain Computers")
    AutoEnrollmentPermissions= @("Domain Computers")
}

# --- Client-side: certreq during scheduled task ------------------------
# GPO-driven autoenrollment engine (certreq.exe) triggers this on
# every login + every 8h. The INF below is what ships to the CA.
@'
[Version]
Signature="$Windows NT$"

[NewRequest]
Subject = "CN=%COMPUTERNAME%.corp.contoso.com"
KeyLength = 2048
KeyAlgorithm = RSA
KeyContainer = "{AutoGen}"
MachineKeySet = TRUE
SMIME = FALSE
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft Platform Crypto Provider"
ProviderType = 23
RequestType = PKCS10
KeyUsage = 0xA0

[Extensions]
2.5.29.17 = "{text}dns=%COMPUTERNAME%.corp.contoso.com"

[RequestAttributes]
CertificateTemplate = WorkstationAuthentication
'@ | Out-File -FilePath $env:TEMP\enroll.inf -Encoding ascii

certreq.exe -new -q $env:TEMP\enroll.inf $env:TEMP\enroll.req
certreq.exe -submit -q -config "dc01.corp.contoso.com\Contoso-Issuing-CA" `
    $env:TEMP\enroll.req $env:TEMP\enroll.cer
certreq.exe -accept -q -machine $env:TEMP\enroll.cer

# --- Ripple effect: scope of RSA dependency ---------------------------
# Each enrolled cert is used for:
#   * 802.1X NAC wired/wireless authentication
#   * SCCM client auth
#   * Windows Hello for Business (when combined with user PIN / TPM)
#   * Inbound IPsec (domain isolation)
#   * SMB signing in high-security configurations
# A factored ADCS Issuing CA key forges every one of these in the
# enterprise simultaneously.
