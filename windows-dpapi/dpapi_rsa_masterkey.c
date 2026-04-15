/*
 * dpapi_rsa_masterkey.c
 *
 * Windows DPAPI (Data Protection API) — RSA in domain master key backup.
 * Sources:
 *   - MSDN: Data Protection API (CryptProtectData, CryptUnprotectData)
 *   - impacket dpapi.py (https://github.com/fortra/impacket)
 *   - dpapick (https://github.com/dfirfpi/dpapick)
 *   - Jean-Michel Picod & Elie Bursztein "Reversing DPAPI and Stealing Windows Secrets Offline" (2010)
 *
 * DPAPI is the Windows mechanism for encrypting secrets tied to user identity:
 *   - Browser saved passwords (Chrome, Firefox, Edge — on Windows)
 *   - Windows Credential Manager (stored network passwords, certificates)
 *   - Outlook email account passwords, PST file encryption
 *   - Remote Desktop Connection saved passwords
 *   - IIS application pool passwords
 *   - WPA/WPA2 WiFi passwords
 *   - Private keys in the Windows certificate store (non-exportable flag bypassed by DPAPI)
 *
 * DPAPI data is encrypted with a key derived from the user's Windows password hash.
 * In a domain environment, the master key is ALSO backed up to the Domain Controller (LSASS)
 * using RSA-2048 encryption — this is the "domain backup key" mechanism.
 *
 * Domain backup key RSA-2048:
 *   - Generated once when DPAPI is first used in the domain
 *   - Stored in Active Directory (CN=BCKUPKEY_*, CN=System, DC=corp, DC=example, DC=com)
 *   - The RSA-2048 private key is held by every Domain Controller
 *   - ONLY the DC can decrypt domain-backed DPAPI master keys
 *   - The RSA-2048 public key is used to wrap the user's DPAPI master key
 *
 * An attacker who has the domain DPAPI backup key RSA-2048 private key can decrypt
 * ANY DPAPI-protected secret from ANY user in the domain — offline, without the user's
 * password, without interactive logon.
 *
 * Mimikatz "lsadump::backupkeys" retrieves the domain backup key via MS-BKRP protocol.
 * SharpDPAPI, impacket's dpapi.py, and other tools can then decrypt DPAPI blobs offline.
 * This is the "domain admin -> decrypt all secrets" path in Active Directory compromise.
 */

#include <windows.h>
#include <dpapi.h>
#include <wincrypt.h>
#include <stdio.h>

/*
 * DPAPI_MASTERKEY structure (simplified, from dpapick research)
 * Stored at: %APPDATA%\Microsoft\Protect\{SID}\{GUID}
 */
typedef struct _DPAPI_MASTERKEY {
    BYTE  Version[4];        /* \x02\x00\x00\x00 */
    GUID  MasterKeyGuid;     /* identifies which master key blob this is */
    BYTE  Policy;
    BYTE  MasterKey[288];    /* encrypted master key, RSA-2048 encrypted for domain backup */
    BYTE  BackupKey[288];    /* domain-backed copy, encrypted with domain RSA-2048 public key */
} DPAPI_MASTERKEY;

/*
 * DOMAIN_BACKUP_KEY structure (RSA-2048 public key used to protect domain master keys)
 * Stored in Active Directory as a BLOB on CN=BCKUPKEY_PREFERRED Secret
 */
typedef struct _DOMAIN_BACKUP_KEY {
    DWORD Version;      /* 2 */
    DWORD KeyLen;       /* 0x200 = 512 bytes for RSA-2048 */
    DWORD CertLen;
    BYTE  Guid[16];     /* key GUID */
    /* Followed by RSA-2048 public key BLOB (PUBLICKEYSTRUC + RSAPUBKEY + modulus) */
    /* The modulus is 256 bytes — this is the CRQC input */
} DOMAIN_BACKUP_KEY;

/*
 * dpapi_protect_data() — encrypt data using DPAPI (calls CryptProtectData).
 *
 * Called by Chrome, Edge, Credential Manager, Outlook, IIS, etc.
 * to protect sensitive data on Windows.
 *
 * The data is encrypted with AES-256 derived from the user's master key.
 * The master key is backed up to the DC using the domain RSA-2048 key.
 */
BOOL
dpapi_protect_data(const BYTE *plaintext, DWORD plaintext_len,
                   DATA_BLOB *protected_blob)
{
    DATA_BLOB input;
    input.cbData = plaintext_len;
    input.pbData = (BYTE *)plaintext;

    /* CryptProtectData wraps the AES-encrypted data with master key metadata.
     * The DPAPI_MASTERKEY for the current user's SID is at:
     * %APPDATA%\Microsoft\Protect\{SID}\{GUID}
     * The master key was backed up to the DC on creation using RSA-2048 wrapping. */
    return CryptProtectData(&input,
                             L"DPAPI blob",   /* description */
                             NULL,            /* no optional entropy */
                             NULL,            /* reserved */
                             NULL,            /* no UI prompt */
                             0,               /* flags */
                             protected_blob);
}

/*
 * dpapi_unprotect_with_domain_key() — decrypt DPAPI blob using domain backup RSA key.
 *
 * This is the OFFLINE DECRYPTION path — no user password needed.
 * Requires: the domain DPAPI backup RSA-2048 PRIVATE KEY (from AD or memory dump).
 *
 * 1. Parse the DPAPI master key file from %APPDATA%\Microsoft\Protect\{SID}\{GUID}
 * 2. Find the domain-backed copy (BackupKey field, RSA-2048 encrypted)
 * 3. RSA-OAEP decrypt BackupKey using the domain private key -> recover master key
 * 4. Derive the AES key from the master key and decrypt the DPAPI blob
 *
 * Mimikatz does exactly this:
 *   lsadump::backupkeys /system:DC01.corp.example.com /export  <- dump domain RSA-2048 key
 *   dpapi::masterkey /in:masterkey_blob /pvk:domain_key.pvk   <- decrypt master key
 *   dpapi::chrome /in:Login Data                               <- decrypt Chrome passwords
 *
 * The attack works offline on any DPAPI blob from any domain user.
 */
BOOL
dpapi_unprotect_with_domain_key(const DPAPI_MASTERKEY *mk_blob,
                                  HCRYPTPROV domain_privkey_prov,
                                  BYTE *master_key_out, DWORD *master_key_len)
{
    HCRYPTKEY hKey;
    BYTE encrypted_mk[288];
    DWORD enc_len = 288;
    BOOL result;

    /* The BackupKey field is the master key encrypted with domain RSA-2048 public key.
     * Decrypt it with the domain private key (obtained from DC via MS-BKRP or LSASS dump).
     *
     * The domain RSA-2048 private key is in:
     *   - LSASS process memory on Domain Controllers (extractable via mimikatz lsadump::backupkeys)
     *   - Active Directory (CN=BCKUPKEY_* in CN=System — readable by domain admins)
     *   - NTDS.DIT backup (offline)
     *
     * Factor the domain RSA-2048 public key (obtainable via ldap/AD query as domain user):
     *   -> derive the RSA-2048 private key
     *   -> decrypt every domain user's DPAPI master key
     *   -> decrypt every DPAPI-protected secret in the entire domain
     *
     * "Every DPAPI-protected secret" includes:
     *   - All Chrome/Edge/Firefox saved passwords for all domain users
     *   - All Windows Credential Manager entries (network passwords, saved logins)
     *   - All Outlook PST/OST passwords and cached Exchange credentials
     *   - All WiFi passwords
     *   - All certificate private keys stored in the Windows cert store
     *   - All IIS application pool service account passwords
     *   - All Azure AD sync account credentials (AADC)
     */

    memcpy(encrypted_mk, mk_blob->BackupKey, 288);

    /* RSA-OAEP decrypt using domain private key */
    /* In CryptoAPI: CryptDecrypt(hKey, 0, TRUE, CRYPT_OAEP, ...) */
    result = CryptImportKey(domain_privkey_prov,
                             (BYTE *)&mk_blob->BackupKey, 288,
                             0, 0, &hKey);
    if (!result) return FALSE;

    result = CryptDecrypt(hKey, 0, TRUE,
                           CRYPT_OAEP,
                           master_key_out,
                           master_key_len);
    CryptDestroyKey(hKey);
    return result;
}

/*
 * get_domain_backup_key_pubkey() — retrieve domain DPAPI backup RSA-2048 public key from AD.
 *
 * Any domain user (read access to AD) can retrieve the public key.
 * It's stored as a SECRET object in Active Directory, but the PUBLIC key portion
 * is readable without special permissions via LDAP query.
 *
 * The public key is also transmitted during the MS-BKRP (Backup Key Remote Protocol)
 * exchange — every time a new master key is backed up to the DC, the DC public key
 * is used for RSA wrapping, and the public key is transmitted to the client.
 *
 * This is the CRQC input for the entire domain's DPAPI security.
 */
void
get_domain_backup_key_pubkey(const char *dc_hostname, BYTE *pubkey_out, DWORD *pubkey_len)
{
    /* MS-BKRP GetBackupKey call retrieves the RSA-2048 public key from the DC.
     * Documented in [MS-BKRP] spec. Any domain-joined computer can call this.
     *
     * Tools that do this:
     *   impacket: dpapi.py backupkeys --target dc01.corp.example.com
     *   mimikatz: lsadump::backupkeys /system:dc01.corp.example.com /export
     *
     * The exported .PVK file contains the RSA-2048 public key in plaintext.
     * Factor it -> derive RSA-2048 private key -> decrypt every DPAPI blob in the domain.
     */
    (void)dc_hostname;
    /* Actual implementation uses [MS-BKRP] RPC calls over SMB/MSRPC */
    *pubkey_len = 0;
}
