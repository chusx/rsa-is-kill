# authenticode-pe — RSA in Windows PE/driver code signing

**Standard:** Microsoft Authenticode (based on PKCS#7 / CMS, RFC 3161 timestamps) 
**Industry:** Windows OS, enterprise software, kernel drivers 
**Algorithm:** RSA-2048 / RSA-4096 (SHA-256 digest) — only supported algorithm in Microsoft's root program 

## What it does

Authenticode is Microsoft's code signing format for Windows binaries. A SHA-256 hash
of the PE image is signed with the publisher's RSA private key and embedded as a PKCS#7
SignedData structure in the file's Certificate Table.

Windows uses Authenticode for:
- **Kernel drivers** — mandatory for 64-bit Windows 10+ (WHCP-signed or via WHQL)
- **SmartScreen filter** — signature determines reputation for downloaded EXEs
- **UAC prompts** — publisher identity comes from the Authenticode cert
- **Windows Update packages** — every .msu, .cab, .msi from Microsoft is Authenticode-signed
- **UEFI Secure Boot shims** — PE images in the UEFI boot chain (see shim-uefi/)
- **PowerShell execution policy** — signed scripts require Authenticode

The Microsoft Trusted Root Program requires RSA-2048 minimum for code signing
certificates. ECDSA is not accepted for code signing in the Microsoft root trust.
The Windows Hardware Compatibility Program (WHCP) portal accepts RSA submissions only.

The Microsoft CA chain for kernel driver signing:
```
Microsoft Root Certificate Authority 2010 (RSA-2048)
 Microsoft Code Signing PCA 2011 (RSA-2048)
 Microsoft Windows Hardware Compatibility Publisher (RSA-2048)
 [driver binary signature]
```

## Why it's stuck

- Microsoft has not defined a non-RSA Authenticode algorithm. The Authenticode specification
 uses PKCS#7 algorithm OIDs; no ML-DSA or SLH-DSA OID is registered for this use
- The WHCP (Hardware Dev Center) portal that signs Windows drivers does not accept non-RSA
 submissions. There is no API or documentation for submitting non-RSA-signed drivers
- Windows XP through Windows 11 all validate Authenticode with the same RSA-based
 path. A non-RSA algorithm would require OS updates to add a new signature validator
- Code signing certificates have 1-3 year validity but the signed binaries are archived
 forever. Old installers, games, business software signed with RSA-2048 remain in
 use for decades

## impact

Authenticode is what Windows uses to decide "is this software from who it says it's from."
the Microsoft Code Signing PCA 2011 RSA-2048 key is used to countersign all WHCP
driver submissions. one key, all Windows kernel driver trust.

- factor the Microsoft Code Signing PCA 2011 RSA-2048 key and you can countersign
 arbitrary kernel drivers that Windows loads without any warning, UAC prompt, or
 security popup. persistent kernel-mode code execution with full trust, no driver
 signing bypass, no SecureBoot workaround needed
- forge Authenticode signatures for any publisher's certificate. malware that presents
 as signed by "Microsoft Corporation" or any legitimate ISV. SmartScreen shows a
 verified publisher, UAC shows the company name, nothing looks wrong
- Windows Update packages are Authenticode-signed. forge signatures for fake updates
 and Windows Update infrastructure will serve and install them
- this affects the entire Windows ecosystem going back to XP. any machine that
 validates Authenticode (all of them) is affected

## Code

`authenticode_rsa_sign.c` — `sign_pe_image()` (PKCS#7 SignedData construction with RSA
signer, from osslsigncode), `pe_calc_digest()` (Authenticode hash of PE image), and
notes on the Microsoft WHCP driver signing chain.
