/*
 * iec62351_rsa.c
 *
 * IEC 62351 security for power substation automation — RSA in IEC 61850 MMS/GOOSE/SV.
 *
 * Sources:
 *   - IEC 62351-3 (TLS for MMS), IEC 62351-5 (digital signatures for GOOSE/SV),
 *     IEC 62351-8 (role-based access control)
 *   - libIEC61850 (https://github.com/mz-automation/libIEC61850)
 *   - OpenIEC61850 (Java, https://github.com/gythialy/openmuc-driver-iec61850)
 *
 * IEC 61850 is the standard for substation automation and protection.
 * It covers:
 *   - MMS (Manufacturing Message Specification) — over TCP — configuration, control
 *   - GOOSE (Generic Object Oriented Substation Event) — over Ethernet multicast
 *     — protection tripping, interlocking (sub-millisecond timing)
 *   - Sampled Values (SV) — over Ethernet multicast — current/voltage measurements
 *
 * IEC 62351-3 specifies TLS for MMS connections. The TLS certificate on the
 * substation IED (Intelligent Electronic Device) is RSA-2048 (typically).
 *
 * IEC 62351-5 specifies signed GOOSE and SV messages. The digital signature
 * on a GOOSE trip message uses RSA (or ECDSA) with a 2048-bit key from the IED.
 *
 * Deployed in:
 *   - ENTSO-E member transmission system operators (all major European grids)
 *   - US bulk electric system IEDs (NERC CIP regulated)
 *   - ABB, Siemens, GE, SEL (Schweitzer Engineering) protection relays
 *   - New high-voltage substations built since ~2010 all use IEC 61850
 */

#include <stdint.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

/* IEC 62351-5 GOOSE signature appended header */
struct goose_sig_appended_header {
    uint8_t  time_to_live;      /* 1 byte */
    uint16_t length;            /* appended header length */
    uint8_t  security_info_tag; /* 0x9D = Security Attribute */
    uint16_t security_info_len;
    uint8_t  msg_auth_code[16]; /* Message Authentication Code (optional) */
    uint8_t  signature_tag;     /* 0x9F = Digital Signature */
    uint16_t signature_len;     /* 256 for RSA-2048 */
    uint8_t  signature[256];    /* RSA-2048 PKCS#1 v1.5 over SHA-256(GOOSE PDU) */
};

/* MMS client certificate (RSA-2048) for IEC 62351-3 TLS mutual auth */
/*
 * iec62351_mms_tls_init() — configure TLS context for IEC 61850 MMS connection.
 *
 * MMS runs over TCP port 102 (via RFC 1006 TPKT). IEC 62351-3 mandates TLS
 * with mutual authentication — both the MMS client (SCADA/EMS) and the server
 * (substation IED) present RSA-2048 certificates.
 *
 * The IED certificate is issued by the substation utility's private PKI
 * (often ABB/Siemens/SEL certificate management tools). The root CA is
 * a utility-operated RSA-2048 CA, not publicly trusted.
 *
 * An attacker who factors the IED's TLS cert can:
 *   - MitM MMS connections (impersonate IED to SCADA, or SCADA to IED)
 *   - Issue unauthorized OPERATE commands (circuit breaker open/close)
 *   - Read/modify IED configuration (protection settings, interlocks)
 */
int
iec62351_mms_tls_init(SSL_CTX *ctx,
                       const char *ied_cert_file,
                       const char *ied_key_file,
                       const char *ca_cert_file)
{
    /* Load IED RSA-2048 certificate */
    if (SSL_CTX_use_certificate_chain_file(ctx, ied_cert_file) <= 0)
        return -1;

    /* Load RSA-2048 private key */
    if (SSL_CTX_use_PrivateKey_file(ctx, ied_key_file, SSL_FILETYPE_PEM) <= 0)
        return -1;

    if (!SSL_CTX_check_private_key(ctx))
        return -1;

    /* Require mutual TLS — IEC 62351-3 mandatory */
    SSL_CTX_set_verify(ctx,
        SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
        NULL);

    SSL_CTX_load_verify_locations(ctx, ca_cert_file, NULL);

    /* TLS 1.2+ only — IEC 62351-3:2020 requires TLS 1.2 minimum */
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                             SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

    return 0;
}

/*
 * iec62351_sign_goose() — sign a GOOSE protection message per IEC 62351-5.
 *
 * GOOSE is a multicast Ethernet protocol for protection relay coordination.
 * A GOOSE "trip" message tells a circuit breaker to open within ~4ms.
 * IEC 62351-5 adds an RSA or ECDSA signature to GOOSE messages to prevent
 * unauthorized trip injection (spoofed GOOSE = open all breakers = blackout).
 *
 * The RSA-2048 signing key is stored in the IED's secure key store.
 * The IED certificate public key is distributed to all subscribing IEDs via
 * the substation configuration tool (SCL/SCD file — XML format, plaintext).
 *
 * TIMING CONSTRAINT: GOOSE trip messages must be processed in < 4ms.
 * RSA-2048 signing takes ~1ms on a Cortex-A9 (typical IED processor).
 * This is why many IED vendors implemented the optional signature and why
 * some substations have it disabled — latency margin is extremely tight.
 */
int
iec62351_sign_goose(const uint8_t *goose_pdu, size_t pdu_len,
                    EVP_PKEY *ied_key,
                    struct goose_sig_appended_header *sig_out)
{
    EVP_MD_CTX *ctx;
    uint8_t digest[32];
    size_t sig_len = 256;
    int ret = -1;

    /* SHA-256 over the GOOSE PDU */
    SHA256(goose_pdu, pdu_len, digest);

    ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, ied_key) <= 0)
        goto out;
    if (EVP_DigestSignUpdate(ctx, digest, 32) <= 0)
        goto out;
    /* RSA-2048 PKCS#1 v1.5 — 256 bytes — appended to GOOSE Ethernet frame */
    if (EVP_DigestSignFinal(ctx, sig_out->signature, &sig_len) <= 0)
        goto out;

    sig_out->signature_tag = 0x9F;
    sig_out->signature_len = (uint16_t)sig_len;
    ret = 0;
out:
    EVP_MD_CTX_free(ctx);
    return ret;
}

/*
 * iec62351_verify_goose() — verify RSA signature on incoming GOOSE trip message.
 *
 * Called by a protection IED when it receives a GOOSE frame from another IED.
 * If the signature is invalid, the trip command SHOULD be discarded.
 * The IED needs the publisher's RSA-2048 public key from the SCD file.
 *
 * Problem: many deployed IEDs have the signature verification DISABLED because:
 *   a) The 4ms timing constraint is hard to meet with RSA verification
 *   b) The SCD key distribution infrastructure was not deployed
 *   c) The option was retrofitted and operators didn't enable it
 *
 * So even where IEC 62351-5 signing is "supported," it often isn't active.
 */
int
iec62351_verify_goose(const uint8_t *goose_pdu, size_t pdu_len,
                      const struct goose_sig_appended_header *sig,
                      EVP_PKEY *publisher_pubkey)
{
    EVP_MD_CTX *ctx;
    uint8_t digest[32];
    int ret;

    SHA256(goose_pdu, pdu_len, digest);

    ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, publisher_pubkey);
    EVP_DigestVerifyUpdate(ctx, digest, 32);
    ret = EVP_DigestVerifyFinal(ctx, sig->signature, sig->signature_len);
    /* 1 = valid GOOSE, process the trip command */
    /* 0 = forged GOOSE, discard */
    /* < 0 = error, vendor-specific behavior (many accept anyway) */

    EVP_MD_CTX_free(ctx);
    return ret;
}
