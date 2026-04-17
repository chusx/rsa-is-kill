/*
 * Illustrative code based on CCSDS 351.0-M-1 (Space Data Link Security)
 * and CCSDS 350.9-G-3 (Security Architecture for Space Data Systems).
 *
 * CCSDS (Consultative Committee for Space Data Systems) is the standard for
 * satellite communications used by NASA, ESA, JAXA, ISRO, DLR, CNSA, and
 * every other space agency. It governs:
 *   - Command uplink (telecommand): ground station → spacecraft
 *   - Telemetry downlink: spacecraft → ground station
 *
 * CCSDS SDLS (Space Data Link Security) provides authentication and encryption
 * of telecommand frames to prevent unauthorized commanding of spacecraft.
 *
 * CCSDS 350.9 §3.6 — Asymmetric key management uses RSA:
 *   - RSA-2048 or RSA-3072 for key establishment (RSA-OAEP)
 *   - ECDSA P-256 / P-384 for digital signatures
 *   - Session keys distributed via RSA key wrap
 *
 * Satellite lifespan: 5-15 years for LEO, up to 30 years for GEO.
 * Spacecraft hardware cannot be updated in orbit.
 * No PQC algorithm is defined in any CCSDS security specification.
 * The CCSDS Security Working Group has not published a PQC roadmap.
 */

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdint.h>

/* CCSDS Telecommand Frame Primary Header */
#define CCSDS_TC_FRAME_MAX_LEN  1024    /* SDLS max frame size */
#define CCSDS_SDLS_AES_KEY_LEN  32      /* AES-256 session key */
#define CCSDS_SDLS_RSA_KEY_BITS 2048    /* RSA key size for key wrap */

typedef struct {
    uint16_t version_scid;   /* 2-bit version + 10-bit Spacecraft ID */
    uint16_t vcid_len;       /* 6-bit VCID + 10-bit frame length */
    uint8_t  seq_num;        /* frame sequence number */
} CCSDS_TC_PrimaryHeader;

typedef struct {
    uint16_t spi;            /* Security Parameter Index */
    uint8_t  iv[16];         /* AES initialization vector */
    uint8_t  mac[16];        /* Message Authentication Code (AES-GCM tag) */
    uint8_t  payload[];      /* encrypted command data */
} CCSDS_SDLS_SecurityHeader;

/*
 * Ground Key Management: RSA key wrap for SDLS session keys.
 *
 * The spacecraft stores the Ground Station's RSA-2048 public key in EEPROM
 * (burned at integration, before launch). Ground commands new session keys
 * by wrapping them with RSA-OAEP and uploading in a Key Transfer Packet.
 *
 * @session_key:    32-byte AES-256 session key (new symmetric key for SDLS)
 * @spacecraft_pubkey: RSA-2048 public key from spacecraft EEPROM
 * @wrapped_key:    Output: RSA-OAEP encrypted session key (256 bytes)
 */
int ccsds_sdls_wrap_session_key(const uint8_t *session_key,
                                 RSA *spacecraft_pubkey,   /* RSA-2048 */
                                 uint8_t *wrapped_key,
                                 size_t *wrapped_len)
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *evp_key = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(evp_key, RSAPublicKey_dup(spacecraft_pubkey));

    ctx = EVP_PKEY_CTX_new(evp_key, NULL);
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);   /* RSA-OAEP */
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());

    /* Encrypt: wrapped_key = RSA-OAEP(spacecraft_pubkey, session_key) */
    int ret = EVP_PKEY_encrypt(ctx, wrapped_key, wrapped_len,
                               session_key, CCSDS_SDLS_AES_KEY_LEN);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(evp_key);
    return ret;
}

/*
 * Key verification: once the spacecraft receives the Key Transfer Packet,
 * it decrypts with its RSA-2048 private key (stored in secure EEPROM).
 * The RSA private key is generated and burned at spacecraft integration.
 * It is never transmitted and cannot be updated after launch.
 *
 * CRQC attack scenario:
 *   1. Spacecraft RSA-2048 public key is published in the CCSDS Key Management
 *      Infrastructure (or extractable from transmitted frames)
 *   2. CRQC factors the modulus → recovers spacecraft RSA-2048 private key
 *   3. Attacker wraps an arbitrary AES session key with spacecraft public key
 *   4. Attacker uploads forged Key Transfer Packet to spacecraft
 *   5. Spacecraft adopts the attacker's session key
 *   6. Attacker can now authenticate any telecommand: attitude changes,
 *      payload power, transponder reconfiguration, orbit maneuvers
 *
 * Notable missions using CCSDS SDLS or equivalent:
 *   - NASA GOES-R series (geostationary weather satellites)
 *   - ESA Sentinel missions (Copernicus Earth observation)
 *   - NASA LADEE, MMS, TESS (science missions)
 *   - Commercial LEO constellations (Starlink uses proprietary, others use CCSDS)
 *
 * HARVEST-NOW-DECRYPT-LATER for space:
 * Command uplinks to GEO satellites are detectable (known uplink frequencies,
 * directional antennas from known ground stations). An adversary recording
 * SDLS Key Transfer Packets today can use a CRQC to compromise future sessions.
 */
