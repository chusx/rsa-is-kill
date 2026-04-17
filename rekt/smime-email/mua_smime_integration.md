# S/MIME mail — how `smime_rsa_sign.c` is exercised in MUAs and MTAs

S/MIME (RFC 8551) wraps email bodies in CMS SignedData /
EnvelopedData structures signed + encrypted with per-user RSA
certificates.  The RSA primitives in `smime_rsa_sign.c` are
invoked every time any of these consumers sends or receives a
signed or encrypted message:

## MUAs

- **Microsoft Outlook (Windows, Mac, iOS, Android) + Exchange
  Online / Exchange Server** — default S/MIME signing for every
  government, DoD, financial, health-insurance tenant. Outlook's
  `IMAPI.ICertStore` hits Windows CAPI/CNG, which calls into
  `ncrypt.dll` / `bcrypt.dll` for the RSA sign; the same
  primitive that `smime_rsa_sign.c` models.
- **Apple Mail (macOS + iOS)** uses the per-user RSA cert from
  Keychain; iOS Mail reads DoD CAC/PIV-derived certs for military
  mail.
- **Mozilla Thunderbird** via NSS — see `nss-firefox/` for the
  underlying RSA verify walk.
- **Mailbird, Evolution (GNOME), KMail (KDE-KWallet), Claws-Mail**
  all wire into gpgsm / NSS / GnuTLS for S/MIME.

## Gateways / MTAs

- **Microsoft Exchange Transport Rules** can strip/attach S/MIME
  headers at org boundary.
- **Cisco Secure Email Gateway (IronPort ESA)** — inbound S/MIME
  decrypt using a per-tenant escrowed key; outbound signing on
  behalf of the domain.
- **Proofpoint Email Encryption, Symantec Encryption (formerly
  PGP Corporation), Microsoft Purview Message Encryption** — all
  have S/MIME integration modes.

## Issuing CAs

- **DoD CAC**: every US DoD active-duty service member, civilian
  employee, and contractor holds three RSA-2048 certs on their
  CAC — one each for identity (PIV auth), email-signing, and
  email-encryption. Email sig/enc is mandatory for any
  classified-but-unclassified correspondence.
- **PIV / PIV-I**: US federal civilian (DHS, DOJ, Treasury, HHS).
- **Entrust, DigiCert, Sectigo, GlobalSign** personal S/MIME
  ("Personal Authentication" or "Class 1/2/3 Secure Email")
  issued to millions of subscribers at regulated employers
  (pharma, law firms, insurance carriers).
- **AeroMACS, SAFE-BioPharma, CertiPath** — industry PKIs whose
  cross-signed trust anchors chain into commercial MUAs for
  aerospace + pharmaceutical signed-email.

## Workflow that lands on the RSA primitive

    compose() → canonicalize headers → CMS SignedData build →
        sign with user's RSA-2048 S/MIME cert → multipart/signed →
        submit to Exchange / Outlook-web / IMAP-Sent

    receive() → parse multipart/signed → extract CMS → chain-verify
        signer cert against org trust store + revocation →
        RSA verify content digest → present "signed by Jane Q.
        Public" badge to user

Both the outbound sign and the inbound verify are the primitive
in `smime_rsa_sign.c`.

## Breakage

A factoring attack against:

- **The DoD Root CA key**: attacker mints CAC-equivalent email-
  signing certs that Outlook / Outlook-Web / Apple Mail treat as
  valid DoD correspondence. Spear-phishing inside the .mil
  namespace becomes indistinguishable from legitimate
  instruction from a commanding officer.  Similar argument for
  Treasury / DHS / DOJ on the civilian side.
- **A commercial S/MIME issuer** (Sectigo, DigiCert Personal ID):
  attacker impersonates executives inside regulated Fortune-500
  tenants; wire-transfer authorization fraud is the obvious
  money-line scenario.
- **An individual's S/MIME cert via leaked key**: historical
  email archives re-interpretable — 15 years of signed legal
  opinions become plausibly-forgeable in litigation.

S/MIME-encrypted archives are the worst case: every message ever
encrypted under a now-factorable RSA key is decryptable by the
attacker forever, because the content-encryption key is
RSA-wrapped in every EnvelopedData recipient info.  Mailbox
archives going back 20+ years at regulated employers are under
retention mandate — all of them become plaintext on day one of a
published break.
