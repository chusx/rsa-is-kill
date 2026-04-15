/*
 * hdcp2_ake_rsa.c
 *
 * HDCP 2.x Authentication and Key Exchange (AKE) — RSA operations.
 * Sources:
 *   - HDCP 2.2 Specification (February 2013, DCP LLC)
 *   - HDCP 2.3 Specification (February 2018, DCP LLC)
 *   - HDCP on HDMI Specification Rev. 2.3
 *   - HDCP on DisplayPort Rev. 2.3
 *
 * Authentication protocol:
 *
 *   Source                                          Sink (Receiver)
 *   ------                                          ---------------
 *   AKE_Init (rtx, TxCaps)          -->
 *                                   <--             AKE_Send_Cert (certrx, rrx, RxCaps)
 *   # source verifies certrx using DCP LLC RSA-3072 public key
 *   # source generates km (128-bit master key)
 *   # source looks up stored pairing if available, otherwise no_stored_km
 *
 *   AKE_No_Stored_km (Ekpub(km))    -->
 *   # E_kpub(km) = RSAES-OAEP-MGF1-SHA-256(km, RSA-1024 sink pubkey)
 *                                   <--             AKE_Send_H_prime (H')
 *   # both derive kd, ks from km using AES-CTR
 *   # stream encryption: AES-128-CTR with ks
 *
 * certrx layout (522 bytes):
 *   [0..4]    Receiver ID (5 bytes, unique per device)
 *   [5..132]  Receiver public key modulus (128 bytes = RSA-1024)
 *   [133..135] Receiver public key exponent (3 bytes, always 01 00 01 or 03)
 *   [136..137] ReservedRx (2 bytes)
 *   [138..521] DCP LLC signature (384 bytes = RSA-3072 PKCS#1 v1.5, SHA-256)
 */

#include <stdint.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include <openssl/evp.h>

#define HDCP2_CERTRX_LEN              522
#define HDCP2_SINK_MODULUS_LEN        128   /* RSA-1024 */
#define HDCP2_DCP_ROOT_MODULUS_LEN    384   /* RSA-3072 */
#define HDCP2_KM_LEN                  16    /* 128-bit master key */
#define HDCP2_EKPUB_KM_LEN            128   /* RSA-1024 ciphertext */

/* DCP LLC root RSA-3072 public key — burned into every HDCP 2.x source.
 * Real value is published in the HDCP 2.x Specification, Section 5.3. */
static const uint8_t DCP_LLC_RSA3072_MODULUS[HDCP2_DCP_ROOT_MODULUS_LEN] = {
    /* ... 384-byte modulus as published by DCP LLC ... */
    0x00
};
static const uint8_t DCP_LLC_RSA3072_EXPONENT[3] = { 0x01, 0x00, 0x01 };

struct hdcp2_certrx {
    uint8_t receiver_id[5];
    uint8_t modulus[HDCP2_SINK_MODULUS_LEN];
    uint8_t exponent[3];
    uint8_t reserved[2];
    uint8_t dcp_signature[HDCP2_DCP_ROOT_MODULUS_LEN];
};

/*
 * hdcp2_verify_certrx — verify receiver certificate was signed by DCP LLC.
 * Called by every HDCP 2.x source at the start of every HDCP session —
 * so billions of times per day worldwide.
 */
int
hdcp2_verify_certrx(const struct hdcp2_certrx *cert)
{
    /* Construct DCP LLC public key from hardcoded modulus + e */
    RSA *dcp_root = RSA_new();
    BIGNUM *n = BN_bin2bn(DCP_LLC_RSA3072_MODULUS, HDCP2_DCP_ROOT_MODULUS_LEN, NULL);
    BIGNUM *e = BN_bin2bn(DCP_LLC_RSA3072_EXPONENT, 3, NULL);
    RSA_set0_key(dcp_root, n, e, NULL);

    /* Message to verify = receiver_id || modulus || exponent || reserved */
    uint8_t msg[5 + HDCP2_SINK_MODULUS_LEN + 3 + 2];
    uint8_t *p = msg;
    memcpy(p, cert->receiver_id, 5); p += 5;
    memcpy(p, cert->modulus, HDCP2_SINK_MODULUS_LEN); p += HDCP2_SINK_MODULUS_LEN;
    memcpy(p, cert->exponent, 3); p += 3;
    memcpy(p, cert->reserved, 2);

    uint8_t digest[32];
    SHA256(msg, sizeof(msg), digest);

    int ok = RSA_verify(NID_sha256, digest, sizeof(digest),
                        cert->dcp_signature, HDCP2_DCP_ROOT_MODULUS_LEN,
                        dcp_root);
    RSA_free(dcp_root);
    return ok;
}

/*
 * hdcp2_encrypt_km — wrap 128-bit master key to sink's RSA-1024 public key
 * using RSAES-OAEP-MGF1 with SHA-256.
 */
int
hdcp2_encrypt_km(const struct hdcp2_certrx *cert,
                  const uint8_t km[HDCP2_KM_LEN],
                  uint8_t ekpub_km[HDCP2_EKPUB_KM_LEN])
{
    RSA *sink_pub = RSA_new();
    BIGNUM *n = BN_bin2bn(cert->modulus, HDCP2_SINK_MODULUS_LEN, NULL);
    BIGNUM *e = BN_bin2bn(cert->exponent, 3, NULL);
    RSA_set0_key(sink_pub, n, e, NULL);

    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(pkey, sink_pub);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());

    size_t outlen = HDCP2_EKPUB_KM_LEN;
    int ok = EVP_PKEY_encrypt(ctx, ekpub_km, &outlen, km, HDCP2_KM_LEN);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    RSA_free(sink_pub);
    return ok;
}

/*
 * hdcp2_derive_ks — derive 128-bit session key from master key using
 * AES-128-CTR as a PRF per HDCP 2.2 Section 2.7.
 */
void
hdcp2_derive_ks(const uint8_t km[HDCP2_KM_LEN],
                 const uint8_t rn[8],
                 uint8_t ks[16])
{
    /* Simplified KDF — real implementation uses dkey generation from km
     * with additional mixing of rtx, rrx, rn. */
    AES_KEY key;
    AES_set_encrypt_key(km, 128, &key);
    uint8_t counter_block[16] = {0};
    memcpy(counter_block, rn, 8);
    AES_encrypt(counter_block, ks, &key);
}

/*
 * Attack scenario (classical poly-time factoring):
 *
 *  1. Build a software HDCP sink that advertises a DCP-LLC-signed certrx
 *     for a receiver whose RSA-1024 private key is known to the attacker.
 *     Forging the certrx requires DCP LLC's RSA-3072 signing key.
 *
 *  2. DCP LLC's RSA-3072 public key is embedded in every HDCP 2.x source
 *     device — trivially extractable by probing any GPU, game console, or
 *     streaming stick. The corresponding modulus is also published in the
 *     HDCP 2.x specification itself. Factor it classically.
 *
 *  3. With the DCP LLC private key, sign a receiver cert for a chosen
 *     RSA-1024 sink keypair. Plug a software "HDMI sink" into any source.
 *     Source verifies the cert (passes), encrypts km to our sink RSA pubkey,
 *     we decrypt km, derive ks, and decrypt every frame of 4K content the
 *     source sends.
 *
 *  4. Result: universal HDCP 2.x bypass. Every UHD Blu-ray, every 4K
 *     streaming service, every HDMI-delivered premium content, available
 *     as clean plaintext off the wire.
 */
