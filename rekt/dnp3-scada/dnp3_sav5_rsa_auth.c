/*
 * Illustrative code based on IEEE Std 1815-2012 (DNP3) Annex A (SAv5) and
 * the DNP3 Secure Authentication Version 5 specification.
 *
 * DNP3 (Distributed Network Protocol 3) is the dominant SCADA protocol for
 * electric power distribution, water/wastewater, and oil & gas pipeline control.
 * SAv5 (Secure Authentication v5) is the security layer for DNP3, specified in
 * IEEE 1815-2012 Annex A.
 *
 * SAv5 uses RSAES-OAEP-1024 for asymmetric key transport (update key wrapping).
 * 1024-bit RSA is classically broken since ~2010 (768-bit factored in 2009).
 * No PQC algorithm is defined in DNP3 SAv5 or its successor SAv6 draft.
 */

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <string.h>

/* DNP3 SAv5 §A.8 — Key Wrap using RSAES-OAEP-1024 */
#define SAV5_RSA_KEY_BITS          1024    /* mandated by SAv5 spec */
#define SAV5_UPDATE_KEY_LEN        16      /* 128-bit AES update key */
#define SAV5_OAEP_HASH             EVP_sha256()

/*
 * SAv5 Key Change Procedure (§A.6):
 * The Outstation (RTU/IED) holds an RSA-1024 public key.
 * The Master sends a new symmetric Update Key wrapped with RSAES-OAEP-1024.
 * All subsequent HMAC-based message authentication uses this update key.
 *
 * RSA-1024: classically factored using GNFS in ~2^80 operations.
 * A CRQC factors it trivially via Shor's algorithm.
 */
int dnp3_sav5_wrap_update_key(const uint8_t *update_key,    /* 16-byte AES-128 key */
                               RSA *outstation_pubkey,       /* RSA-1024 public key */
                               uint8_t *wrapped_key_out,
                               int *wrapped_len)
{
    EVP_PKEY *evp_key = EVP_PKEY_new();
    EVP_PKEY_CTX *ctx = NULL;
    size_t out_len;
    int ret = -1;

    EVP_PKEY_assign_RSA(evp_key, RSAPublicKey_dup(outstation_pubkey));
    ctx = EVP_PKEY_CTX_new(evp_key, NULL);

    EVP_PKEY_encrypt_init(ctx);
    /* RSAES-OAEP padding per SAv5 §A.8.3.1 */
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx, SAV5_OAEP_HASH);

    /* Get output size (128 bytes for RSA-1024) */
    EVP_PKEY_encrypt(ctx, NULL, &out_len, update_key, SAV5_UPDATE_KEY_LEN);

    /* Encrypt — result is RSA-1024 ciphertext. A CRQC decrypts this trivially. */
    ret = EVP_PKEY_encrypt(ctx, wrapped_key_out, &out_len,
                           update_key, SAV5_UPDATE_KEY_LEN);
    *wrapped_len = (int)out_len;

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(evp_key);
    return ret;
}

/*
 * SAv5 Aggressive Mode HMAC (after key exchange):
 * Once the update key is established (via RSA key wrap), all DNP3 messages
 * are authenticated with HMAC-SHA256. But the update key itself was transmitted
 * under RSA-1024 — if that was recorded, it can be decrypted retroactively.
 *
 * Harvest-Now-Decrypt-Later (HNDL) attack scenario:
 *   1. Adversary records all SAv5 Key Change procedure traffic (2015-2025)
 *   2. CRQC becomes available (2030s)
 *   3. Adversary factors RSA-1024 outstation public keys
 *   4. Decrypts stored Update Key ciphertext
 *   5. Can now replay or forge any historical/current DNP3 authentication
 *
 * Critical infrastructure targets: substations, pump stations, pipeline RTUs.
 * IED (Intelligent Electronic Device) firmware updates are infrequent.
 * Many DNP3 devices have 15-30 year lifespans with no crypto agility.
 */

/* SAv5 Key Status message — RSA public key distribution */
typedef struct {
    uint8_t  key_change_method;   /* 0x03 = RSA-1024 with SHA-256 OAEP */
    uint16_t key_wrap_algo;       /* 0x0005 = RSAES-OAEP-1024 */
    uint8_t  public_key[140];     /* DER-encoded RSA-1024 public key */
    uint16_t public_key_len;
} SAv5_KeyStatusResponse;
