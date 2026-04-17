/*
 * dds_security_plugin.c
 *
 * DDS-Security Authentication plugin glue for an SROS2 domain.
 * This is the hook that runs on every DDS discovery handshake between
 * ROS 2 nodes on an autonomous robot or across a robot fleet.
 *
 * The plugin implements the OMG DDS-Security v1.1 "BuiltinPlugins"
 * handshake: two participants exchange Handshake Request / Reply / Final
 * messages carrying nonces signed by the RSA identity keys. Both sides
 * verify the peer's identity cert chains to the Identity CA.
 *
 * Relevant implementations this skeleton mirrors:
 *   - eProsima Fast DDS `fastrtps::security::AuthenticationPlugin`
 *   - RTI Connext DDS Secure `security::authentication::*`
 *   - Eclipse Cyclone DDS Security
 */

#include <stdint.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/rand.h>


struct dds_handshake_ctx {
    X509       *identity_ca;          /* fleet's Identity CA cert */
    X509       *local_identity_cert;  /* this node's cert */
    EVP_PKEY   *local_identity_key;   /* this node's RSA private key */

    uint8_t     challenge_local[32];
    uint8_t     challenge_peer[32];
    X509       *peer_identity_cert;
    EVP_PKEY   *peer_identity_pubkey;
};


/* Validate a peer's identity certificate (received inline in the
 * Handshake Request message) against the fleet's Identity CA. */
static int
validate_peer_cert(struct dds_handshake_ctx *ctx,
                    const uint8_t *peer_cert_der, size_t der_len)
{
    const uint8_t *p = peer_cert_der;
    X509 *peer = d2i_X509(NULL, &p, der_len);
    if (!peer) return -1;

    /* Verify peer cert's RSA-SHA256 signature against Identity CA */
    EVP_PKEY *ca_pk = X509_get_pubkey(ctx->identity_ca);
    int ok = X509_verify(peer, ca_pk);
    EVP_PKEY_free(ca_pk);
    if (ok != 1) { X509_free(peer); return -1; }

    ctx->peer_identity_cert = peer;
    ctx->peer_identity_pubkey = X509_get_pubkey(peer);
    return 0;
}


/* Produce a Handshake Reply: our node signs SHA-256(peer_challenge ||
 * our_challenge || peer_cert_fingerprint || local_cert_fingerprint)
 * with our RSA identity key. Peer verifies this to complete mutual auth. */
static int
produce_handshake_reply(struct dds_handshake_ctx *ctx,
                         uint8_t *signature_out, size_t *sig_len_out)
{
    RAND_bytes(ctx->challenge_local, 32);

    uint8_t to_sign[32 + 32 + 32 + 32];
    memcpy(to_sign, ctx->challenge_peer, 32);
    memcpy(to_sign + 32, ctx->challenge_local, 32);

    /* Cert fingerprints (SHA-256 over DER) */
    uint8_t peer_fp[32], local_fp[32];
    {
        int len;
        uint8_t *der = NULL;
        len = i2d_X509(ctx->peer_identity_cert, &der);
        SHA256(der, len, peer_fp);
        OPENSSL_free(der);
        der = NULL;
        len = i2d_X509(ctx->local_identity_cert, &der);
        SHA256(der, len, local_fp);
        OPENSSL_free(der);
    }
    memcpy(to_sign + 64, peer_fp, 32);
    memcpy(to_sign + 96, local_fp, 32);

    uint8_t hash[32];
    SHA256(to_sign, sizeof(to_sign), hash);

    EVP_PKEY_CTX *sctx = EVP_PKEY_CTX_new(ctx->local_identity_key, NULL);
    EVP_PKEY_sign_init(sctx);
    EVP_PKEY_CTX_set_signature_md(sctx, EVP_sha256());

    size_t siglen = 256;   /* RSA-2048 */
    int rc = EVP_PKEY_sign(sctx, signature_out, &siglen, hash, 32);
    EVP_PKEY_CTX_free(sctx);

    *sig_len_out = siglen;
    return rc == 1 ? 0 : -1;
}


/* Verify peer's Handshake Final signature in the mirror direction:
 * peer signs SHA-256(our_challenge || peer_challenge || local_fp || peer_fp). */
static int
verify_handshake_final(struct dds_handshake_ctx *ctx,
                        const uint8_t *signature, size_t sig_len)
{
    uint8_t to_verify[32 + 32 + 32 + 32];
    memcpy(to_verify, ctx->challenge_local, 32);
    memcpy(to_verify + 32, ctx->challenge_peer, 32);

    uint8_t local_fp[32], peer_fp[32];
    {
        int len;
        uint8_t *der = NULL;
        len = i2d_X509(ctx->local_identity_cert, &der);
        SHA256(der, len, local_fp);
        OPENSSL_free(der);
        der = NULL;
        len = i2d_X509(ctx->peer_identity_cert, &der);
        SHA256(der, len, peer_fp);
        OPENSSL_free(der);
    }
    memcpy(to_verify + 64, local_fp, 32);
    memcpy(to_verify + 96, peer_fp, 32);

    uint8_t hash[32];
    SHA256(to_verify, sizeof(to_verify), hash);

    EVP_PKEY_CTX *vctx = EVP_PKEY_CTX_new(ctx->peer_identity_pubkey, NULL);
    EVP_PKEY_verify_init(vctx);
    EVP_PKEY_CTX_set_signature_md(vctx, EVP_sha256());

    int rc = EVP_PKEY_verify(vctx, signature, sig_len, hash, 32);
    EVP_PKEY_CTX_free(vctx);
    return rc == 1 ? 0 : -1;
}


/*
 * The handshake, if it succeeds, feeds into DDS-Security's Key Agreement
 * plugin (Diffie-Hellman MODP-2048 by default, but increasingly ECDH
 * curve25519 in newer deployments) to derive the session AES-GCM keys
 * that encrypt every subsequent DDS sample on the wire.
 *
 * An attacker who has forged RSA identity (via Identity CA compromise)
 * gets a seat at DDS discovery and then has full access to encrypted
 * topics, because they completed the handshake legitimately from the
 * plugin's perspective.
 */
