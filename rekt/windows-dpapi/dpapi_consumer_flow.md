# Windows DPAPI — where `dpapi_rsa_masterkey.c` is actually invoked

DPAPI (Data Protection API) is the per-user/per-machine secret-
sealing service that every Windows process on every domain-joined
and non-domain-joined Windows box silently leans on.  Under the
hood, DPAPI seals and unseals symmetric keys under a master key
that is itself protected by a per-user RSA keypair (for
domain-joined machines, a copy of the user's RSA private master-
key blob is also escrowed at the DC). The primitive in
`dpapi_rsa_masterkey.c` is invoked whenever DPAPI is.

## Direct callers

- **Chrome, Edge, Brave, Opera, Vivaldi** — all Chromium browsers
  seal the saved-password database under DPAPI. Every
  user-credential-manager password in the browser is effectively
  RSA-master-key-protected.
- **Outlook** — `.ost` PST-encrypted local cache, and
  mail-account stored credentials (IMAP/POP/Exchange) all go
  through DPAPI.
- **Microsoft Edge WebView2** / **Internet Explorer (legacy)
  AutoComplete** — AutoComplete passwords live under DPAPI.
- **Wi-Fi** — stored 802.1X credentials, PSKs for auto-reconnect
  SSIDs.
- **Remote Desktop Connection Manager, Stored User Names &
  Passwords Control Panel applet** — saved RDP session credentials.
- **Windows Hello for Business** — PRT (Primary Refresh Token)
  encryption-at-rest.
- **AzureAD Broker / Web Account Manager (WAM)** — every SSO token
  for Entra ID desktop integration.
- **Skype for Business / Teams classic** — local token cache.
- **OneDrive, Dropbox, Box, iCloud for Windows** — auth tokens.
- **EFS (Encrypting File System)** — per-file FEK is RSA-wrapped
  to the user's EFS cert, which itself lives under DPAPI.

## Attacker-relevant tools (for authorized use in red-team /
forensics)

- **Mimikatz** `sekurlsa::dpapi`, `lsadump::backupkeys`,
  `dpapi::masterkey`, `dpapi::chrome` — the canonical DPAPI
  offensive tool.  Its success depends on either (a) the current
  user being logged in so LSASS holds the derived key, or (b)
  possession of the domain backup RSA private key so any user's
  masterkey can be decrypted without their password.
- **SharpDPAPI / DonPAPI / impacket `dpapi.py`** — same operation
  over network protocols + exported hives.

## Flow (what `dpapi_rsa_masterkey.c` is part of)

1. User logs on. LSA derives an SHA-1/SHA-512 of the password,
   unwraps the user's master-key file at
   `%APPDATA%\Microsoft\Protect\{SID}\{mk_guid}`.
2. The master-key file contains (a) a password-derived-key-
   encrypted blob, and (b) an RSA-encrypted copy of the same
   master key under the domain DC's public backup key. Recovery
   path: even if the user forgets their password, the domain
   admin can restore the master key via the DC's RSA private
   key.
3. Every `CryptProtectData` / `CryptUnprotectData` call thereafter
   derives a per-blob symmetric key from the master key and
   seals/unseals the caller's plaintext.
4. EFS-specific variant uses the user's EFS RSA-2048 cert (stored
   in `{user}\AppData\Roaming\Microsoft\SystemCertificates\My`)
   as a second-layer wrap over the FEK.

## Domain-controller backup key

For every AD domain, `domain\NTDS` stores two RSA keypairs:

- `BCKUPKEY_PREFERRED` — current preferred backup key.
- `BCKUPKEY_P` — historical/legacy.

Both are RSA-2048 (older forests RSA-1024, a known weakness).
LSA on every domain-joined workstation negotiates with the DC at
first logon to fetch the public half and includes the RSA-wrapped
copy in every master-key file.  This is what makes Mimikatz
`lsadump::backupkeys` catastrophic when the DC key is exfiltrated.

## Breakage

A factoring attack against:

- **The DC BCKUPKEY_PREFERRED**: attacker decrypts every DPAPI
  master key for every user in the domain, historic and current.
  Every saved browser password, every OAuth token, every Outlook
  IMAP cred, every WAM PRT, every stored RDP secret — all
  retroactively recoverable from captured master-key hive
  exports. Multi-year detection-and-response tail because DPAPI
  blobs from years of backups remain decryptable.
- **An individual user's EFS cert** (RSA-2048): attacker decrypts
  that user's EFS files.  Unrecoverable without the private key in
  the general case; the DC backup key can re-encrypt only if the
  recovery agent cert is enrolled, which many home/workgroup
  boxes don't have.

No post-break recovery short of forced password reset for every
user in the forest + EFS re-enrollment + bulk re-seal of every
DPAPI consumer.  Estimated cleanup per Fortune-500 enterprise:
6–12 months.
