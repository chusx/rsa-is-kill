/*
 * Illustrative code based on ETCS (European Train Control System) specs:
 *   - ERA/ERTMS/033281 — ETCS On-Board / Track-side security requirements
 *   - SUBSET-114 — ETCS On-Board Unit Secure Data Download
 *   - ERA_ERTMS_015560 — ETCS cryptographic requirements
 *
 * ERTMS/ETCS (European Train Control and Management System) is the unified
 * train protection and control standard for European railways. It is being
 * deployed across 30+ countries, ~100,000 km of railway.
 *
 * ETCS security architecture:
 *   - X.509 certificates for all on-board units (OBUs) and Radio Block Centres (RBCs)
 *   - TLS mutual authentication for RBC-OBU GSM-R/LTE radio link
 *   - SUBSET-114: firmware/data package signing uses RSA-2048
 *   - Certificate validity: up to 5 years (but OBU hardware lasts 20-30 years)
 *
 * No PQC algorithm is specified in any ETCS or ERTMS security document.
 * The ERA (European Union Agency for Railways) has not published PQC guidance.
 */

#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <stdint.h>

/* ETCS Certificate Authority hierarchy:
 *   ERA Root CA (RSA-4096 or ECDSA-P384)
 *     └── National CA (RSA-2048 per country, 20yr validity)
 *           └── OBU Certificate (RSA-2048, 5yr validity, burned at manufacture)
 *           └── RBC Certificate (RSA-2048, 5yr validity)
 *
 * The OBU (On-Board Unit) certificate is the hardware identity of the train.
 * It authenticates the train to lineside equipment and the National CA.
 * OBU hardware lifespan: 20-30 years. Certificate can be renewed,
 * but key material is stored in tamper-resistant hardware (SIM-like module).
 */

typedef struct {
    X509 *obu_cert;         /* On-Board Unit X.509 certificate (RSA-2048) */
    EVP_PKEY *obu_privkey;  /* RSA-2048 private key in tamper-protected storage */
    X509 *rbc_cert;         /* Radio Block Centre certificate */
    X509_STORE *era_trust;  /* ERA PKI trust store */
} ETCS_PKI_Context;

/* TLS mutual authentication between OBU and RBC.
 * Both sides present X.509 certificates. Both certificates are RSA-2048.
 * This authenticates the train to the signalling system before movement authority
 * is granted. A forged OBU certificate could allow an adversary to receive
 * movement authorities (proceed orders) for arbitrary train IDs.
 */
int etcs_obu_rbc_tls_auth(SSL_CTX *ctx,
                           const ETCS_PKI_Context *pki)
{
    /* Configure OBU certificate (RSA-2048) for TLS client auth */
    SSL_CTX_use_certificate(ctx, pki->obu_cert);
    SSL_CTX_use_PrivateKey(ctx, pki->obu_privkey);   /* RSA-2048 private key */

    /* Trust store: ERA Root CA → National CA → RBC certificate */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_cert_store(ctx, pki->era_trust);

    /* Cipher suites: TLS_RSA_WITH_AES_128_CBC_SHA256 or
     * TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (both require RSA certificate) */
    SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-GCM-SHA384:RSA-AES128-SHA256");

    return 0;
}

/* SUBSET-114: Secure Data Download — firmware/database update authentication.
 * New ETCS versions, balise databases, and speed restriction updates are
 * signed by the ERA or national authority with RSA-2048.
 * The OBU verifies the signature before applying any update.
 */
int etcs_verify_data_package(const uint8_t *package, size_t package_len,
                              const uint8_t *signature, size_t sig_len,
                              EVP_PKEY *era_signing_key)   /* RSA-2048 */
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ret;

    EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, era_signing_key);
    EVP_DigestVerifyUpdate(ctx, package, package_len);
    ret = EVP_DigestVerifyFinal(ctx, signature, sig_len);  /* RSA-2048 verify */

    EVP_MD_CTX_free(ctx);
    return (ret == 1) ? 0 : -1;
}

/*
 * Safety-critical implications:
 *
 * ETCS Level 2/3 operation: trains move under continuous supervision from the
 * RBC. The RBC grants Movement Authorities (MAs) — permission to proceed to
 * a specific point at a specific speed. If OBU-RBC authentication is forged:
 *   - Adversary could inject false MAs: "proceed at 200 km/h through red signal"
 *   - Or deny MAs: "emergency stop entire line" (denial of service)
 *
 * Railway PKI is operated per-country. The German DB, French SNCF, UK Network
 * Rail, and ~25 other national PKIs all issue RSA certificates to OBUs.
 * Coordinating PQC migration across all of these simultaneously is
 * not practically achievable without a multi-year ERA mandate and budget.
 *
 * GSM-R (current radio): end-of-life 2030. FRMCS (Future Railway Mobile
 * Communication System) is the successor — still uses X.509 with RSA,
 * no PQC defined in FRMCS security architecture (3GPP TR 22.889).
 */
