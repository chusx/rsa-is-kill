# gnupg-openpgp-card — RSA on OpenPGP smartcards (YubiKey, Nitrokey, GNUK)

**Repository:** git.gnupg.org — `scd/app-openpgp.c` 
**Industry:** Developer security, German government, privacy-focused orgs, security researchers 
**Algorithm:** RSA-2048 / RSA-4096 on OpenPGP Card v1/v2/v3 smartcards 

## What it does

The OpenPGP Card specification defines a smartcard that stores RSA (or ECC) keypairs
in hardware. GnuPG's smartcard daemon (`scd`) talks to these cards via PCSC or CCID.
When signing or decrypting, the hash or ciphertext is sent to the card; the card
performs the RSA operation internally; the private key never leaves the card.

Physical cards:
- **YubiKey 5 series** — supports RSA-2048/4096 and ECC on the OpenPGP applet
- **Nitrokey Pro 2 / Start** — heavy use in German government, privacy-focused organizations
- **GNUK** — open hardware, used by security researchers
- **Feitian ePass** — widely deployed in Asia, supports OpenPGP Card

Used by:
- Developers using `gpg --card-status` and `gpg --use-agent` for code signing and email
- German BSI recommends OpenPGP cards for document signing
- Security researchers storing signing keys in hardware
- Organizations using card-based SSH authentication (`gpg-agent --enable-ssh-support`)

GnuPG uploads the RSA public key to keyservers (keys.openpgp.org, keyserver.ubuntu.com)
automatically. The public key is the input an attacker needs, and it's been public since the key
was first generated.

## Why it's stuck

- OpenPGP Card v1.0 through v2.1 support only RSA. These cards cannot do ECC or non-RSA
 at all — the firmware is read-only silicon. They still work; they just can't be upgraded
- OpenPGP Card v3.0+ (2018) added ECC, but non-RSA key types are not in v3.4 (the current spec)
- YubiKey's OpenPGP applet has no ML-DSA key type. Yubico would need a new applet spec
 and firmware + hardware update
- The OpenPGP Card spec is maintained by the GNU project / GnuPG developers.
 There is no non-RSA working group within the OpenPGP Card effort
- GnuPG scd (`scd/app-openpgp.c`) has hardcoded key attribute parsing for RSA and ECC.
 Adding ML-DSA requires spec changes, card firmware, and scd updates simultaneously

## impact

OpenPGP card RSA keys are people's personal signing and encryption keys, often used
for years or decades. the public key is published on keyservers. this is HNDL at
the individual level.

- every GPG-encrypted message ever sent to a person with an RSA-2048 OpenPGP card
 key is retroactively decryptable once the factoring break derives the private key from their
 public key on the keyserver. all their archived encrypted email, all their encrypted
 files — gone. the hardware protection was never relevant to this attack
- code signing: developers who sign git commits or packages with OpenPGP card RSA keys.
 forge their signatures on any commit or package. the hardware card that "protects"
 the key is irrelevant because the attack uses the public key
- Nitrokey in German government: government officials who use Nitrokey for document
 signing. forge their signatures on government documents. legally binding in Germany
 (SigG qualified electronic signatures)
- SSH authentication via gpg-agent: the OpenPGP card auth key RSA public key is
 in `~/.ssh/authorized_keys` on remote servers. a factoring break derives private key, impersonates
 the user to every server they authenticate to

## Code

`openpgp_card_rsa.c` — `do_sign()` (COMPUTE DIGITAL SIGNATURE APDU, RSA-2048 signing
on card), `do_decipher()` (RSA decryption for session key recovery), and
`app_openpgp_getattr()` (RSA public key export to keyservers). From `scd/app-openpgp.c`
on `git.gnupg.org`.
