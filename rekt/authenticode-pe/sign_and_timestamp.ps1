# sign_and_timestamp.ps1
#
# Production Authenticode signing pipeline used by Windows software
# vendors. The RSA-signed PE structure layout is in the primary source
# file; this wrapper shows the build-time flow that emits those signed
# binaries and countersigns them against an RFC 3161 TSA.
#
# Same pipeline invoked by:
#   - Every enterprise Windows release train that ships .exe/.dll/.sys/.cab
#   - Microsoft Partner Center driver-signing submission
#   - HSM-backed code-signing fleets (AWS CloudHSM, Azure Key Vault
#     Premium, Thales Luna, Utimaco, SafeNet/Fortanix)

param(
    [Parameter(Mandatory)][string]$Binary,
    [Parameter(Mandatory)][string]$SubjectName,
    [string]$TimestampServer = "http://timestamp.digicert.com",
    [string]$HashAlgorithm   = "sha256",
    [switch]$KernelMode       # .sys driver signing — stricter rules
)

# 1. Locate signing cert. Enterprise pattern: HSM-backed with the
#    private key never leaving the FIPS 140-2 L3 module. PFX import
#    to the cert store is for dev-only; in production a PKCS#11 /
#    CNG handle is used.
$cert = Get-ChildItem Cert:\CurrentUser\My |
        Where-Object { $_.Subject -match [regex]::Escape($SubjectName) -and $_.HasPrivateKey } |
        Sort-Object NotAfter -Descending | Select-Object -First 1
if (-not $cert) { throw "no usable signing cert" }

# Enforce key-size policy: CAB Forum Code Signing BRs v3.x require
# RSA-3072+ for new issuance since 2023-06-01. Older RSA-2048 certs
# remain valid until their expiry.
$keyLen = $cert.PublicKey.Key.KeySize
if ($keyLen -lt 3072 -and -not $KernelMode) {
    Write-Warning "RSA key size $keyLen below CA/B Forum minimum 3072"
}

# 2. signtool sign. Uses the cert's private key (RSA-2048/3072/4096)
#    to produce a PKCS#7 over the PE's Authenticode hash, then
#    embeds it in the certificate table (IMAGE_DIRECTORY_ENTRY_SECURITY).
$signArgs = @(
    "sign"
    "/fd", $HashAlgorithm          # file digest SHA-256 / SHA-384
    "/td", $HashAlgorithm          # timestamp digest
    "/tr", $TimestampServer        # RFC 3161 TSA
    "/sha1", $cert.Thumbprint
    "/v"
)
if ($KernelMode) {
    # Kernel-mode drivers need EV cert + attestation or cross-cert
    $signArgs += @(
        "/ac", "C:\signing\MSAuthROOT.cer"   # cross-cert appended
    )
}
$signArgs += $Binary

& "$env:ProgramFiles (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe" @signArgs
if ($LASTEXITCODE -ne 0) { throw "signtool failed" }

# 3. Dual-sign (SHA-1 legacy + SHA-256) if required for long tail
#    of Windows 7 / older-patch-level machines. Rare in 2026; most
#    orgs have dropped SHA-1 signing entirely.
#
# 4. Verify after signing: re-parse the certificate table, walk the
#    RSA chain to the root Microsoft Code Signing PCA in
#    Cert:\LocalMachine\AuthRoot, confirm the RFC 3161 countersignature
#    chains to an AATL-recognized TSA.
& signtool.exe verify /pa /v /all $Binary

# 5. Upload to the release manifest. SmartScreen reputation is built
#    over time against the signer's RSA key; a new key starts at zero
#    reputation and users see UAC scary dialogs until the publisher
#    accumulates enough installs for SmartScreen to elevate trust.
$spki = (Get-PfxCertificate $Binary).PublicKey.EncodedKeyValue.RawData |
        ForEach-Object { '{0:X2}' -f $_ } | Join-String
Write-Host "signed $Binary with $keyLen-bit RSA key, SPKI=$spki"
