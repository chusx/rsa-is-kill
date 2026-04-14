/*
 * Source: MIT Kerberos krb5 - https://github.com/krb5/krb5
 * File:   src/plugins/preauth/pkinit/pkinit_crypto_openssl.c
 * Reference: RFC 4556 (PKINIT), MS-PKCA (Microsoft PKINIT extension)
 * License: MIT
 *
 * Relevant excerpt: PKINIT uses RSA certificates for Kerberos authentication.
 *
 * PKINIT (Public Key Cryptography for Initial Authentication) is the
 * mechanism that allows smart cards, TPMs, and certificate-based auth
 * to work with Kerberos / Active Directory.  It is also the foundation
 * of Windows Hello for Business, Azure AD certificate authentication,
 * and enterprise PKI-based SSO across every major enterprise.
 *
 * The client presents an RSA certificate to the KDC (Key Distribution
 * Center, i.e. the Domain Controller).  The KDC validates the RSA
 * signature and issues a Kerberos TGT.  That TGT then grants access
 * to every Kerberized service (file shares, Exchange, SharePoint, etc.).
 *
 * If RSA is broken:
 *   - Forge any user's PKINIT certificate → get their Kerberos TGT
 *   - With a valid TGT, access any service the user has rights to
 *   - This is a full Active Directory domain compromise vector
 *   - No PKINIT PQC RFC exists; no KDC implements PQC cert validation
 */

/*
 * Client-side: sign the authentication request with the client's RSA key.
 * This produces the authPack signed attribute in the AS-REQ message.
 * The KDC will verify this RSA signature against the client's certificate.
 */
static krb5_error_code
pkinit_sign_data(krb5_context context,
                 pkinit_identity_crypto_context id_cryptoctx,
                 unsigned char *data, unsigned int data_len,
                 unsigned char **sig, unsigned int *sig_len)
{
    EVP_MD_CTX  *ctx = NULL;
    EVP_PKEY    *pkey = id_cryptoctx->my_key;  /* client RSA private key */
    krb5_error_code retval = 0;

    ctx = EVP_MD_CTX_new();
    /* SHA-256 with RSA PKCS#1 v1.5 padding - the standard PKINIT sign op */
    if (!EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey))
        goto cleanup;
    if (!EVP_DigestSignUpdate(ctx, data, data_len))
        goto cleanup;
    /* EVP_DigestSignFinal calls RSA_sign() on the SHA-256 hash */
    if (!EVP_DigestSignFinal(ctx, NULL, (size_t *)sig_len))
        goto cleanup;
    *sig = malloc(*sig_len);
    if (!EVP_DigestSignFinal(ctx, *sig, (size_t *)sig_len))
        goto cleanup;
    /* sig now contains the RSA-signed authPack.
     * A CRQC can forge this for any user whose certificate is known
     * (certificates are public — they're in LDAP / Active Directory). */
cleanup:
    EVP_MD_CTX_free(ctx);
    return retval;
}

/*
 * KDC-side: verify the client's RSA signature on the authentication data.
 * Called during AS-REQ processing for every certificate-based login.
 * certificate chain validated against the enterprise PKI (also RSA).
 */
static krb5_error_code
pkinit_verify_data(krb5_context context,
                   pkinit_kdc_crypto_context kdc_cryptoctx,
                   unsigned char *data, unsigned int data_len,
                   unsigned char *sig, unsigned int sig_len,
                   X509 *client_cert)  /* RSA certificate from AD */
{
    EVP_PKEY    *pkey = X509_get_pubkey(client_cert);  /* RSA public key */
    EVP_MD_CTX  *ctx = EVP_MD_CTX_new();
    int          ret;

    EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey);
    EVP_DigestVerifyUpdate(ctx, data, data_len);
    ret = EVP_DigestVerifyFinal(ctx, sig, sig_len);
    /* ret == 1: valid.  A CRQC-forged signature returns 1. */
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return (ret == 1) ? 0 : KRB5KDC_ERR_INVALID_SIG;
}
