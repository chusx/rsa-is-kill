<#
    ndes_scep_enroll.ps1

    Windows Network Device Enrollment Service (NDES) is the
    SCEP front-end used by Intune/MDM, Cisco ISE, Aruba
    ClearPass, and every mid-market network-access-control
    stack to provision RSA-2048 client certs onto laptops,
    phones, and 802.1X-connecting equipment.

    The NDES challenge-password is signed by the RA cert; the
    client's CSR is then signed by the issuing CA (an ADCS
    subordinate) whose root is the enterprise root. Everything
    chains to a single RSA root that is typically RSA-2048 or
    RSA-4096, installed once during AD forest deployment and
    never rotated.

    The code below is the attacker-facing surface: what an
    admin's workstation / Intune connector does during
    enrollment. If the RA or CA RSA key is factored, an
    attacker mints arbitrary smartcard-logon / 802.1X /
    VPN / S/MIME certs that the entire enterprise trusts.
#>

param(
    [Parameter(Mandatory)] [string] $NdesUrl,
    [Parameter(Mandatory)] [string] $ChallengePassword,
    [Parameter(Mandatory)] [string] $SubjectDN,
    [string] $TemplateOid = "1.3.6.1.4.1.311.21.8.1.2.4",   # User
    [ValidateSet("RSA","ECDSA")] [string] $Alg = "RSA",
    [int] $KeyLen = 2048
)

# -----------------------------------------------------------------
#  1. Key generation on TPM-backed CNG provider. For NDES-enrolled
#     smartcard alt, store ends up in 'Microsoft Smart Card Key
#     Storage Provider'. Either way the public half ends in a
#     CSR that we PKCS#7-wrap below.
# -----------------------------------------------------------------
$cng = New-Object 'System.Security.Cryptography.CngKeyCreationParameters'
$cng.Provider = [System.Security.Cryptography.CngProvider]::new(
    "Microsoft Platform Crypto Provider")
$cng.KeyUsage = [System.Security.Cryptography.CngKeyUsages]::Signing
$cng.ExportPolicy =
    [System.Security.Cryptography.CngExportPolicies]::None

$algName = if ($Alg -eq "RSA") { "RSA" } else { "ECDSA_P256" }
$key = [System.Security.Cryptography.CngKey]::Create(
    [System.Security.Cryptography.CngAlgorithm]::$algName,
    $null, $cng)

# -----------------------------------------------------------------
#  2. Build PKCS#10 CSR. Subject DN, SAN (userPrincipalName for
#     smartcard logon), and the Microsoft template OID in the
#     szOID_CERTIFICATE_TEMPLATE extension.
# -----------------------------------------------------------------
$req = New-Object 'System.Security.Cryptography.X509Certificates.CertificateRequest' `
    -ArgumentList $SubjectDN, $key, "SHA256"

# Smart-card-logon EKU + client-auth EKU
$ekuOids = [System.Security.Cryptography.OidCollection]::new()
$ekuOids.Add([System.Security.Cryptography.Oid]::new("1.3.6.1.4.1.311.20.2.2")) | Out-Null
$ekuOids.Add([System.Security.Cryptography.Oid]::new("1.3.6.1.5.5.7.3.2"))   | Out-Null
$req.CertificateExtensions.Add(
    [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new(
        $ekuOids, $false))

$csrDer = $req.CreateSigningRequest()

# -----------------------------------------------------------------
#  3. SCEP PKIMessage (RFC 8894). This is a CMS SignedData whose
#     encapContentInfo is EnvelopedData wrapping the CSR. The
#     EnvelopedData is key-transported to the CA's RSA encryption
#     cert — which is the RSA dependency we care about.
# -----------------------------------------------------------------
function Build-PkiMessage {
    param($csrBytes, $challenge, $recipientRsaCert)

    # EnvelopedData: RSA-PKCS1v15 key-transport of a random 3DES/AES key
    $env = [System.Security.Cryptography.Pkcs.EnvelopedCms]::new(
        [System.Security.Cryptography.Pkcs.ContentInfo]::new($csrBytes))
    $recipient = [System.Security.Cryptography.Pkcs.CmsRecipient]::new(
        $recipientRsaCert)
    $env.Encrypt($recipient)

    # SignedData: sign the EnvelopedData blob with a self-signed
    # ephemeral certificate. Include SCEP transaction attributes.
    $signed = [System.Security.Cryptography.Pkcs.SignedCms]::new(
        [System.Security.Cryptography.Pkcs.ContentInfo]::new($env.Encode()))
    $signer = [System.Security.Cryptography.Pkcs.CmsSigner]::new(
        New-SelfSignedEphemeral)
    # SCEP attributes: messageType=PKCSReq(19), transactionID, senderNonce
    $signer.SignedAttributes.Add(
        (New-Object 'System.Security.Cryptography.Pkcs.Pkcs9AttributeObject' `
            -ArgumentList "2.16.840.1.113733.1.9.2",
                [byte[]]@(0x13,0x02,0x31,0x39)))
    $signer.SignedAttributes.Add(
        (New-Object 'System.Security.Cryptography.Pkcs.Pkcs9AttributeObject' `
            -ArgumentList "2.16.840.1.113733.1.9.7",
                [System.Text.Encoding]::UTF8.GetBytes($challenge)))
    $signed.ComputeSignature($signer, $false)
    return $signed.Encode()
}

# -----------------------------------------------------------------
#  4. HTTP POST to NDES. GetCACert first, then PKIOperation.
# -----------------------------------------------------------------
$cacaps  = Invoke-WebRequest "$NdesUrl?operation=GetCACaps"
$cacert  = Invoke-WebRequest "$NdesUrl?operation=GetCACert"
$raCert  = Parse-CACertChain $cacert.Content   # <- RSA, chain to ADCS

$pkiMsg  = Build-PkiMessage $csrDer $ChallengePassword $raCert

$resp = Invoke-WebRequest -Method Post `
    -Uri "$NdesUrl?operation=PKIOperation" `
    -ContentType "application/x-pki-message" `
    -Body $pkiMsg

# Response is a PKIMessage with messageType=CertRep(3) containing
# our freshly-issued ADCS RSA cert signed by the issuing CA.
$issued = Unwrap-PkiMessage $resp.Content
Install-CertWithKey $issued $key

# ---- Forgery surface once ADCS root RSA is factored -------------
# * RA cert RSA factored: attacker forges the SCEP signer and NDES
#   issues a cert for any subject without needing $ChallengePassword.
# * Root/Issuing CA RSA factored: skip NDES entirely — mint a
#   smartcard-logon cert for any UPN, PKINIT yields TGT as
#   Domain Admin. CVE-2022-26923 generalized to every forest.
# * Subordinate encryption cert RSA factored: decrypt archived
#   NDES/MDM enrollments = harvest every provisioned key.
#
# Detection: Defender for Identity flags anomalous TGTs, but the
# cert chain validates. Recovery = new PKI hierarchy + every
# domain-joined device re-enrolled; typical F500 program: 18-36
# months, tens of millions of $.
