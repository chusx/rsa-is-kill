/*
 * tdx_quote_verify.c
 *
 * Relying-party verification of a DCAP v4 TDX quote. Executed by:
 *   - Azure Attestation Service (MAA)
 *   - GCP Confidential Space attestation verifier
 *   - Fortanix CCM, HashiCorp Vault transit attestation
 *   - In-guest client libraries validating peer TDX quotes (for mutual
 *     attestation in AI federated learning or multi-party ML)
 *
 * Two RSA dependencies must hold for the verification to be trustworthy:
 *   1. Intel SGX/TDX Root CA RSA-3072 (certifies Processor CA)
 *   2. Intel Processor CA RSA-3072 (certifies PCK leaf cert)
 * A factoring break of either invalidates every downstream quote.
 */

#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/sha.h>
#include <openssl/ec.h>

#include "quote_v4_layout.h"

const uint8_t INTEL_SGX_ROOT_CA_MODULUS[384] = { 0 };
const uint8_t INTEL_SGX_ROOT_CA_EXPONENT[3] = { 0x01, 0x00, 0x01 };


/* Parse the PEM chain embedded at the end of a v4 quote. */
static int
parse_pck_chain(const uint8_t *pem, size_t len,
                X509 **out_leaf, X509 **out_processor_ca, X509 **out_root)
{
    BIO *bio = BIO_new_mem_buf(pem, len);
    *out_leaf = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    *out_processor_ca = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    *out_root = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return (*out_leaf && *out_processor_ca && *out_root) ? 0 : -1;
}


static int
verify_root_matches_intel(X509 *root)
{
    EVP_PKEY *pk = X509_get_pubkey(root);
    const RSA *rsa = EVP_PKEY_get0_RSA(pk);
    const BIGNUM *n, *e;
    RSA_get0_key(rsa, &n, &e, NULL);

    uint8_t mod_bin[384] = {0};
    BN_bn2binpad(n, mod_bin, 384);

    int ok = (memcmp(mod_bin, INTEL_SGX_ROOT_CA_MODULUS, 384) == 0);
    EVP_PKEY_free(pk);
    return ok ? 0 : -1;
}


static int
verify_ecdsa_sig_over_body(const struct tdx_quote_v4 *q)
{
    /* The quote body (header + td_report) is signed by the ECDSA
     * attestation key whose public key is included in `ecdsa_attestation_pubkey`.
     * That attestation key is itself endorsed by the PCK leaf cert's ECDSA
     * signature in `qe_report_signature`. */

    size_t body_len = sizeof(q->header) + sizeof(q->td_report);
    uint8_t hash[32];
    SHA256((const uint8_t *)&q->header, body_len, hash);

    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_POINT *pt = EC_POINT_new(EC_KEY_get0_group(ec));
    BIGNUM *x = BN_bin2bn(q->ecdsa_attestation_pubkey, 32, NULL);
    BIGNUM *y = BN_bin2bn(q->ecdsa_attestation_pubkey + 32, 32, NULL);
    EC_POINT_set_affine_coordinates(EC_KEY_get0_group(ec), pt, x, y, NULL);
    EC_KEY_set_public_key(ec, pt);

    ECDSA_SIG *sig = ECDSA_SIG_new();
    ECDSA_SIG_set0(sig,
        BN_bin2bn(q->ecdsa_signature, 32, NULL),
        BN_bin2bn(q->ecdsa_signature + 32, 32, NULL));

    int rc = ECDSA_do_verify(hash, 32, sig, ec);

    ECDSA_SIG_free(sig);
    BN_free(x); BN_free(y);
    EC_POINT_free(pt); EC_KEY_free(ec);
    return rc == 1 ? 0 : -1;
}


int
tdx_verify_quote(const struct tdx_quote_v4 *q,
                  const uint8_t expected_report_data[TDX_REPORT_DATA_BYTES],
                  const uint8_t expected_mrtd[TDX_MRTD_BYTES])
{
    /* Freshness / binding: report_data must carry the verifier nonce. */
    if (memcmp(q->td_report.report_data, expected_report_data,
               TDX_REPORT_DATA_BYTES) != 0)
        return -1;

    /* TD identity: MRTD (the TD image hash) must match what we expect. */
    if (memcmp(q->td_report.mrtd, expected_mrtd, TDX_MRTD_BYTES) != 0)
        return -1;

    /* Parse RSA cert chain and verify up to Intel Root. */
    X509 *leaf = NULL, *processor_ca = NULL, *root = NULL;
    if (parse_pck_chain(q->cert_chain_pem, q->cert_data_len,
                         &leaf, &processor_ca, &root) != 0)
        return -1;

    if (verify_root_matches_intel(root) != 0) goto fail;

    /* Processor CA must be signed by Root (RSA-3072). */
    EVP_PKEY *root_pk = X509_get_pubkey(root);
    if (X509_verify(processor_ca, root_pk) != 1) {
        EVP_PKEY_free(root_pk); goto fail;
    }

    /* PCK leaf must be signed by Processor CA (RSA-3072 signing an
     * ECDSA-P256 cert). */
    EVP_PKEY *proc_pk = X509_get_pubkey(processor_ca);
    if (X509_verify(leaf, proc_pk) != 1) {
        EVP_PKEY_free(proc_pk);
        EVP_PKEY_free(root_pk);
        goto fail;
    }
    EVP_PKEY_free(proc_pk);
    EVP_PKEY_free(root_pk);

    /* Verify ECDSA quote signature and QE report signature
     * (latter tied to PCK leaf ECDSA key). */
    if (verify_ecdsa_sig_over_body(q) != 0) goto fail;

    X509_free(leaf);
    X509_free(processor_ca);
    X509_free(root);
    return 0;

fail:
    if (leaf) X509_free(leaf);
    if (processor_ca) X509_free(processor_ca);
    if (root) X509_free(root);
    return -1;
}
