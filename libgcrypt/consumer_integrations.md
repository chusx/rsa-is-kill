# libgcrypt consumers — where the RSA primitives in `libgcrypt_rsa.c` actually run

libgcrypt is the crypto library that GnuPG carved out and turned into a
general-purpose primitive, used well beyond gpg itself.  This index
captures the major production consumers that drive the `gcry_pk_encrypt
/ gcry_pk_decrypt / gcry_pk_sign / gcry_pk_verify` RSA code paths.

## GNOME / Freedesktop stack

- **GNOME Keyring** (`gnome-keyring-daemon`): wraps per-user secrets with
  RSA-wrapped symmetric keys backed by the user's login password. On
  every Fedora/Ubuntu/Debian GNOME desktop on Earth.
- **seahorse** (PGP key manager UI) — thin frontend, but exposes gcrypt
  RSA keygen flow to end users.
- **evolution-data-server**: S/MIME + OpenPGP email encryption/
  signing for Evolution mail.

## KDE stack

- **KWallet** (KDE secrets manager): same pattern as GNOME Keyring.
- **KMail / KOrganizer** S/MIME + OpenPGP plumbing.

## System services

- **systemd-cryptsetup** with `--pkcs11-token` option: unlocks LUKS
  volumes by decrypting a wrapped master key with a PKCS#11 token's
  RSA-2048 key.  Used for FDE on enterprise laptops + servers with
  TPM-free policy.
- **fwupd / LVFS updater**: downloads signed Jcat signature
  archives; jcat re-uses gpgme for PGP/RSA verification.  Every GNOME /
  KDE / Server / RHEL desktop update that touches firmware goes through
  here.
- **OSTree / Flatpak / Flathub**: ostree commit objects signed with
  RSA-2048 PGP keys; Flathub and Fedora Silverblue/Kinoite both verify
  via libgcrypt.
- **libotr / Pidgin / Adium OTR plugin**: Off-the-Record long-term
  identity keys are libgcrypt RSA.
- **libssh** (optional — can also build on libcrypto) hostkey + user
  key RSA.

## GnuPG family directly

- `gpg` / `gpg2` — every OpenPGP signing, verifying, encrypting op.
- `gpgsm` — S/MIME and X.509 equivalent path (Secunet DFN-PKI,
  BundesDruckerei eID use gpgsm + smartcard backends).
- `scdaemon` — smart-card daemon; interfaces with OpenPGP card / PIV
  applets + caches public parameters for libgcrypt.
- `dirmngr` — fetches OCSP + CRLs over libgcrypt TLS helpers.

## Distros / embedded

- Debian `dpkg-source` verifies `.dsc` files through gpgv (libgcrypt
  under the hood).
- Debian / Ubuntu security updates verify `InRelease` via the archive
  keyring and libgcrypt at `apt update` time.
- Yocto / OpenEmbedded `oe-core` includes libgcrypt as a default
  crypto backend for build signing.
- pacman-key (Arch Linux): RSA verification of package database
  signatures via gpgme → libgcrypt.

## Relationship to the RSA crypto in `libgcrypt_rsa.c`

`libgcrypt_rsa.c` implements `gcry_pk_{sign,verify,encrypt,decrypt}` for
the `GCRY_PK_RSA` algorithm family, including PKCS#1 v1.5 padding,
PSS, OAEP, and the unpadded raw operation.  Every consumer above
ultimately reaches one of those four entry points for an RSA
operation.

## Breakage footprint under an RSA factoring attack

- **Per-user secret stores**: everything in GNOME Keyring / KWallet
  becomes trivially extractable from a stolen `~/.local/share/keyrings`
  directory.
- **Disk encryption key-slot unlocks**: PKCS#11-unlocked LUKS volumes
  lose their at-rest confidentiality.
- **Software update trust**: Debian apt, Fedora dnf (via rpm — separate
  example directory), Flathub, LVFS, ostree — every update channel
  that chains its authenticity to libgcrypt RSA falls.
- **Every GnuPG user** on a libgcrypt build (~all major Linux distros).

## Migration cadence

GnuPG has been shipping Ed25519/Curve25519 support since 2.1, but the
installed base of RSA-4096 primary keys is still dominant in enterprise
deployments (key rotation is painful; many keyrings carry keys from
2008-2012). The practical migration primitive is: push a new Ed25519
primary at next key-rollover, cross-sign with the existing RSA primary.
