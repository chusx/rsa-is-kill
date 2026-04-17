# libgcrypt — RSA in GNU Libgcrypt (GnuPG, systemd, KDE, GNOME)

**Repository:** git.gnupg.org (GNU project, not GitHub) 
**Industry:** Linux desktop, servers, government (FIPS 140-2 validated), package management 
**Algorithm:** RSA-2048 through RSA-4096 via gcry_pk_sign/verify/decrypt 

## What it does

Libgcrypt is the GNU cryptographic library — the low-level crypto backend for GnuPG
and a large slice of the Linux ecosystem. It is FIPS 140-2 validated (certificate #2616),
which makes it the required crypto library for US government Red Hat deployments.

Used by:
- **GnuPG** — all RSA signing, decryption, and key operations go through `gcry_pk_sign()` / `gcry_pk_decrypt()` / `gcry_pk_verify()` which call into `cipher/rsa.c`
- **systemd** — journal forward-secure sealing uses RSA via libgcrypt. Every systemd-journald instance on Fedora/RHEL generates an RSA keypair for FSS
- **GNOME Keyring / libsecret** — stores and retrieves RSA keys for GNOME applications
- **KDE Wallet (kwallet)** — uses libgcrypt for key operations
- **GnuTLS** — uses libgcrypt for some asymmetric operations
- **rpm-gpg** — package signature verification on Red Hat systems

The key format is S-expressions (Lisp-style): `(private-key (rsa (n ...) (e ...) (d ...) (p ...) (q ...) (u ...)))`. All RSA operations call `_gcry_mpi_powm()` — multi-precision modular exponentiation.

## Why it's stuck

- Libgcrypt has no non-RSA algorithm registered. `gcry_pk_algo_info(GCRY_PK_ML_DSA, ...)` does not exist
- The GnuPG non-RSA experimental branch (Kyber + Dilithium hybrid) uses a separate crypto layer, not libgcrypt. It's not in any released GnuPG version
- FIPS 140-2 validation of libgcrypt covers RSA operations. Adding non-RSA requires a new FIPS validation cycle (expensive, takes 1-2 years)
- systemd FSS uses libgcrypt RSA directly in C code with no abstraction layer for algorithm replacement

## impact

libgcrypt is the crypto backend for package management and system authentication
on a huge portion of Linux servers. also, systemd uses it to sign journal logs,
which is the forensic record of what happened on a system.

- GnuPG RSA keys signed with libgcrypt are the trust chain for rpm package verification
 on RHEL/CentOS/Fedora. forge an RPM package signature and it installs without warning
 on any server that trusts that key. this is the package manager supply chain attack
- systemd journal FSS uses RSA for forward-secure sealing of system logs. forge the RSA
 journal signature and you can create or modify log entries that look cryptographically
 authentic. the forensic integrity of every RHEL server's event log is gone
- GNOME Keyring and KDE Wallet store credentials protected by RSA. compromise the
 master RSA key and you get all credentials stored in the desktop keyring: SSH keys,
 API tokens, OAuth tokens, saved passwords
- libgcrypt is FIPS 140-2 validated and required in US government Linux deployments.
 the RSA operations in the validated module are the ones that break

## Code

`libgcrypt_rsa.c` — `rsa_generate()` (keypair generation), `rsa_sign()` (PKCS#1 v1.5/PSS
via `_gcry_mpi_powm()`), `rsa_verify()` (verification), and `gnupg_decrypt_session_key_rsa()`
showing how GnuPG calls `gcry_pk_decrypt()` to unwrap encrypted session keys.
From `cipher/rsa.c` in `git.gnupg.org`.
