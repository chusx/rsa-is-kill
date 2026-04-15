# windows-dpapi — RSA-2048 in Windows DPAPI domain backup key (all domain secrets)

**Repository:** Windows CryptoAPI / DPAPI (proprietary); impacket dpapick  
**Industry:** Enterprise Windows Active Directory — essentially all corporate environments  
**Algorithm:** RSA-2048 (domain DPAPI backup key stored in Active Directory, wraps every user's DPAPI master key)  
**PQC migration plan:** None — Microsoft has not announced any PQC migration for the DPAPI domain backup key; the key format is defined in [MS-BKRP] which has no PQC revision

## What it does

Windows DPAPI (Data Protection API) encrypts secrets on Windows: Chrome/Edge/Firefox saved
passwords, Credential Manager entries, Outlook PST passwords, WiFi keys, certificate private
keys, IIS app pool passwords. In a domain environment, DPAPI master keys are backed up to
the Domain Controller using RSA-2048 encryption — this is the "domain backup key" mechanism
defined in the [MS-BKRP] protocol.

The domain backup key is a single RSA-2048 keypair:
- Private key: held by every Domain Controller (in LSASS memory and AD secret objects)
- Public key: used to wrap every new DPAPI master key for every user in the domain

Any domain user can retrieve the RSA-2048 public key via the MS-BKRP protocol (or LDAP).
The public key wraps every domain user's DPAPI master key. If you have the RSA-2048 private
key, you can decrypt DPAPI master keys offline for every user who has ever logged in to
the domain — with their DPAPI data files (from their profile), no password required.

This is already a known Active Directory attack: `mimikatz lsadump::backupkeys` retrieves
the key from DC memory. Then `dpapi::masterkey` + `dpapi::chrome` decrypts Chrome passwords
for any user. The tools exist. The only thing stopping bulk offline decryption of a stolen
AD is that you need domain admin to dump the private key. With RSA broken, you need only
the public key — which any domain user can fetch.

## Why it's stuck

- The domain DPAPI backup key RSA-2048 is generated once per domain and almost never rotated.
  Rotating it would require re-encrypting every user's master key file and distributing updates.
  For a large enterprise with thousands of users, this is a significant operation.
- Microsoft's [MS-BKRP] protocol spec does not define PQC key types. Changing the algorithm
  requires a protocol update and client/server updates simultaneously.
- DPAPI is a Windows core subsystem. Changes require OS updates across the entire domain.
- The attack via RSA factoring doesn't require any current Microsoft or customer action
  to enable — the public key has been in AD since the domain was stood up, years ago.
  HNDL: steal the domain DPAPI public key now, factor it later, decrypt all archived
  DPAPI data files you've collected.

## impact

the domain DPAPI backup key is the master key to every domain user's stored secrets.
passwords, certificates, OAuth tokens, everything Windows protects with DPAPI.

- retrieve the RSA-2048 DPAPI public key from any domain controller via LDAP (any
  domain user can do this via impacket `dpapi.py backupkeys`). factor it. derive the
  RSA-2048 private key. now you can decrypt every DPAPI-protected file in the domain
  offline, with no LSASS dump, no domain admin credentials.
- "every DPAPI-protected file" means: all Chrome/Edge/Firefox saved passwords for every
  domain user, all Windows Credential Manager entries (network logins, saved passwords),
  all Outlook account passwords and PST encryption keys, all WiFi passwords for every user
  who connected to corporate WiFi, all certificate private keys in the Windows cert store.
- for Azure AD Connect: the AADC service account's credential for Azure AD sync is
  DPAPI-protected. AADC has Global Admin equivalent access to Azure AD. decrypting AADC
  credentials = full Azure tenant compromise, from the domain DPAPI RSA key alone.
- HNDL: corporate DPAPI data files are frequently backed up (they're in user profiles,
  which are backed up as a matter of policy). steal/obtain backup archives now. factor
  the domain RSA-2048 key when CRQC is available. decrypt all historical DPAPI archives
  from the backup. recover passwords for accounts that may no longer exist but were used
  for things that still matter.
- the mimikatz path (dump LSASS to get the private key directly) requires domain admin.
  the RSA factoring path (factor the public key) requires being a domain user. or just
  having a packet capture of a DPAPI backup operation, which includes the public key.

## Code

`dpapi_rsa_masterkey.c` — `dpapi_protect_data()` (CryptProtectData, triggers domain RSA-2048
key backup), `dpapi_unprotect_with_domain_key()` (CryptDecrypt CRYPT_OAEP with domain RSA-2048
private key, offline master key recovery), `get_domain_backup_key_pubkey()` (MS-BKRP public key
retrieval). mimikatz/impacket toolchain reference and AADC compromise chain in comments.
