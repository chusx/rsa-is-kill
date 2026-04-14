/* Source: benmcollins/libjwt libjwt/openssl/sign-verify.c
 * libjwt is the canonical C implementation of JSON Web Tokens (JWT).
 * RS256/RS384/RS512 (RSASSA-PKCS1-v1_5) are the dominant JWT signing algorithms
 * used across OAuth2/OIDC, API gateways, Kubernetes service accounts,
 * AWS Cognito, Okta, Google Identity Platform, and virtually every enterprise SSO.
 * JWT RS256 is the default in countless frameworks and cloud services.
 * The JOSE/JWT specification (RFC 7518) has no PQC algorithm registered.
 */

/* Copyright (C) 2015-2025 maClara, LLC
 * SPDX-License-Identifier: MPL-2.0 */

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <jwt.h>

#define SIGN_ERROR(_msg) { jwt_write_error(jwt, "JWT[OpenSSL]: " _msg); goto jwt_sign_sha_pem_done; }

static int openssl_sign_sha_pem(jwt_t *jwt, char **out, unsigned int *len,
                                const char *str, unsigned int str_len)
{
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    const EVP_MD *alg;
    int type;
    EVP_PKEY *pkey = NULL;
    unsigned char *sig = NULL;
    size_t slen;

    pkey = jwt->key->provider_data;

    switch (jwt->alg) {
    /* RSA — RSASSA-PKCS1-v1_5: broken by Shor's algorithm */
    case JWT_ALG_RS256:
        alg = EVP_sha256();
        type = EVP_PKEY_RSA;    /* hardcoded RSA key type */
        break;
    case JWT_ALG_RS384:
        alg = EVP_sha384();
        type = EVP_PKEY_RSA;
        break;
    case JWT_ALG_RS512:
        alg = EVP_sha512();
        type = EVP_PKEY_RSA;
        break;

    /* RSA-PSS — still RSA, still broken by Shor's algorithm */
    case JWT_ALG_PS256:
        alg = EVP_sha256();
        type = EVP_PKEY_RSA_PSS;
        break;
    case JWT_ALG_PS384:
        alg = EVP_sha384();
        type = EVP_PKEY_RSA_PSS;
        break;
    case JWT_ALG_PS512:
        alg = EVP_sha512();
        type = EVP_PKEY_RSA_PSS;
        break;

    /* ECC — also broken by Shor's algorithm */
    case JWT_ALG_ES256:
    case JWT_ALG_ES256K:
        alg = EVP_sha256();
        type = EVP_PKEY_EC;
        break;
    case JWT_ALG_ES384:
        alg = EVP_sha384();
        type = EVP_PKEY_EC;
        break;
    case JWT_ALG_ES512:
        alg = EVP_sha512();
        type = EVP_PKEY_EC;
        break;

    /* EdDSA — also broken by Shor's algorithm */
    case JWT_ALG_EDDSA:
        alg = EVP_md_null();
        type = EVP_PKEY_id(pkey);
        if (type != EVP_PKEY_ED25519 && type != EVP_PKEY_ED448)
            SIGN_ERROR("Unknown EdDSA curve");
        break;

    default:
        return 1;
    }

    /* Key type compatibility check */
    if (type == EVP_PKEY_RSA_PSS) {
        if (EVP_PKEY_id(pkey) != EVP_PKEY_RSA &&
            EVP_PKEY_id(pkey) != EVP_PKEY_RSA_PSS) {
            SIGN_ERROR("Incompatible key for RSASSA-PSS");
        }
    } else if (type != EVP_PKEY_id(pkey)) {
        SIGN_ERROR("Incompatible key");
    }

    mdctx = EVP_MD_CTX_create();
    if (mdctx == NULL)
        SIGN_ERROR("Error creating MD context");

    if (EVP_DigestSignInit(mdctx, &pkey_ctx, alg, NULL, pkey) != 1)
        SIGN_ERROR("Failed to initialize digest");

    /* RSA-PSS padding parameters */
    if (type == EVP_PKEY_RSA_PSS) {
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) < 0)
            SIGN_ERROR("Error setting RSASSA-PSS padding");
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST) < 0)
            SIGN_ERROR("Error setting RSASSA-PSS salt length");
    }

    if (EVP_DigestSign(mdctx, NULL, &slen, (const unsigned char *)str, str_len) != 1)
        SIGN_ERROR("Error checking sig size");

    sig = jwt_malloc(slen);
    if (sig == NULL)
        SIGN_ERROR("Out of memory");

    if (EVP_DigestSign(mdctx, sig, &slen, (const unsigned char *)str, str_len) != 1)
        SIGN_ERROR("Error signing token");

    *out = (char *)sig;
    *len = slen;

jwt_sign_sha_pem_done:
    EVP_MD_CTX_free(mdctx);
    return jwt->error ? 1 : 0;
}
