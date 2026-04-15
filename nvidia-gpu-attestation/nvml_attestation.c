/*
 * nvml_attestation.c
 *
 * Verifier-side parsing and RSA-3072 signature check for an NVIDIA GPU
 * attestation report. Runs on the relying-party side — the CVM owner
 * before releasing model weights, or a cloud control plane (Azure
 * Attestation, GCP Confidential Space verifier, on-prem Fortanix
 * Confidential Computing Manager).
 */

#include <stdint.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "attestation_report.h"

const uint8_t NVIDIA_ATTEST_ROOT_MODULUS[512] = { 0 };   /* published pubkey */
const uint8_t NVIDIA_ATTEST_ROOT_EXPONENT[3] = { 0x01, 0x00, 0x01 };


static int
verify_rsa3072_sig(const uint8_t *message, size_t msg_len,
                    const uint8_t *signature,
                    EVP_PKEY *public_key)
{
    uint8_t hash[48];
    SHA384(message, msg_len, hash);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(public_key, NULL);
    if (!ctx) return -1;
    if (EVP_PKEY_verify_init(ctx) <= 0) goto fail;
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha384()) <= 0) goto fail;

    int rc = EVP_PKEY_verify(ctx, signature, 384, hash, 48);
    EVP_PKEY_CTX_free(ctx);
    return rc == 1 ? 0 : -1;
fail:
    EVP_PKEY_CTX_free(ctx);
    return -1;
}


static EVP_PKEY *
nvidia_root_pkey(void)
{
    RSA *rsa = RSA_new();
    BIGNUM *n = BN_bin2bn(NVIDIA_ATTEST_ROOT_MODULUS, 512, NULL);
    BIGNUM *e = BN_bin2bn(NVIDIA_ATTEST_ROOT_EXPONENT, 3, NULL);
    RSA_set0_key(rsa, n, e, NULL);

    EVP_PKEY *pk = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pk, rsa);
    return pk;
}


/* Verify the device cert chain: leaf (device) <- intermediate <- NVIDIA Root.
 * Returns the leaf cert's public key on success (caller frees). */
static EVP_PKEY *
verify_cert_chain(const uint8_t *der, size_t der_len)
{
    X509_STORE *store = X509_STORE_new();
    EVP_PKEY *root_pkey = nvidia_root_pkey();

    /* Parse concatenated DER certs: leaf, then intermediate */
    const uint8_t *p = der;
    X509 *leaf = d2i_X509(NULL, &p, der_len);
    if (!leaf) goto fail;
    size_t leaf_len = p - der;

    X509 *intermediate = d2i_X509(NULL, &p, der_len - leaf_len);
    if (!intermediate) goto fail;

    /* Verify intermediate was signed by NVIDIA root */
    if (X509_verify(intermediate, root_pkey) != 1) goto fail;

    /* Verify leaf was signed by intermediate */
    EVP_PKEY *interm_pk = X509_get_pubkey(intermediate);
    if (X509_verify(leaf, interm_pk) != 1) { EVP_PKEY_free(interm_pk); goto fail; }
    EVP_PKEY_free(interm_pk);

    EVP_PKEY *leaf_pk = X509_get_pubkey(leaf);
    X509_free(leaf);
    X509_free(intermediate);
    EVP_PKEY_free(root_pkey);
    X509_STORE_free(store);
    return leaf_pk;

fail:
    if (leaf) X509_free(leaf);
    EVP_PKEY_free(root_pkey);
    X509_STORE_free(store);
    return NULL;
}


int
nv_verify_attestation_report(const struct nv_attest_report *report,
                              const uint8_t expected_nonce[NV_ATTEST_NONCE_BYTES],
                              const struct nv_rim_id *expected_rim)
{
    /* 1. Nonce must match the verifier-supplied challenge (freshness). */
    if (memcmp(report->body.nonce, expected_nonce,
               NV_ATTEST_NONCE_BYTES) != 0)
        return -1;

    /* 2. CC mode must be ON and not DEVTOOLS. */
    if (report->body.cc_mode != NV_CC_MODE_ON)
        return -1;

    /* 3. RIM identity must match the expected policy
     *    (e.g., "H100 80GB SXM with firmware 96.00.74.00.11"). */
    if (memcmp(&report->body.rim, expected_rim,
               sizeof(struct nv_rim_id)) != 0)
        return -1;

    /* 4. Verify cert chain up to NVIDIA Attestation Root. */
    EVP_PKEY *device_pk = verify_cert_chain(
        report->cert_chain_der, report->cert_chain_len);
    if (!device_pk) return -1;

    /* 5. Verify the RSA-3072 attestation signature over the report body. */
    int rc = verify_rsa3072_sig(
        (const uint8_t *)&report->body, sizeof(report->body),
        report->signature, device_pk);
    EVP_PKEY_free(device_pk);

    return rc;
}


/*
 * The NVIDIA Remote Attestation Service (NRAS) implements the same
 * verification logic above and wraps the outcome in an RS256 JWT:
 *
 *   {
 *     "iss": "nras.attestation.nvidia.com",
 *     "iat": 1733000000,
 *     "nbf": 1733000000,
 *     "exp": 1733003600,
 *     "x-nvidia-gpu-arch": "HOPPER",
 *     "x-nvidia-gpu-ccmode": "ON",
 *     "x-nvidia-gpu-driver-rim": "...",
 *     "measres": "success",
 *     "eat_nonce": "<hex>"
 *   }
 *
 * Enterprise verifiers (Azure Attestation Service, Fortanix CCM, HashiCorp
 * Vault) pin the NRAS JWKS endpoint and treat a positive JWT as sufficient
 * proof of a genuine CC-mode GPU. Factoring the NRAS RSA-3072 signing key
 * lets an attacker mint these JWTs for any non-CC or counterfeit GPU.
 */
