/*
 * Source: OpenVPN - https://github.com/OpenVPN/openvpn
 * File:   src/openvpn/ssl_openssl.c
 * License: GPLv2
 *
 * Relevant excerpt: RSA external key support for TLS authentication.
 * OpenVPN wires a custom RSA_METHOD into OpenSSL so that private key
 * operations (signing, encryption) can be delegated to an external
 * process (e.g. a management interface or hardware token).
 * The algorithm is hardcoded to RSA - there is no equivalent path
 * for a post-quantum key type.
 */

static int
tls_ctx_use_external_rsa_key(struct tls_root_ctx *ctx, EVP_PKEY *pkey)
{
    RSA *rsa = NULL;
    RSA_METHOD *rsa_meth;
    const RSA *pub_rsa = EVP_PKEY_get0_RSA(pkey);

    rsa_meth = RSA_meth_new("OpenVPN external private key RSA Method",
                            RSA_METHOD_FLAG_NO_CHECK);
    RSA_meth_set_pub_enc(rsa_meth, rsa_pub_enc);
    RSA_meth_set_priv_enc(rsa_meth, rsa_priv_enc);

    rsa = RSA_new();
    RSA_get0_key(pub_rsa, &n, &e, NULL);
    RSA_set0_key(rsa, BN_dup(n), BN_dup(e), NULL);
    SSL_CTX_use_RSAPrivateKey(ctx->ctx, rsa);
}

/*
 * RSA private-encrypt callback: called by OpenSSL during TLS handshake
 * to sign the ServerKeyExchange or CertificateVerify message.
 * Padding is either PKCS#1 v1.5 or raw (for TLS 1.3 PSS), but the
 * key type is always RSA - no agility here.
 */
static int
rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to,
             RSA *rsa, int padding)
{
    int len = RSA_size(rsa);
    if (padding != RSA_PKCS1_PADDING && padding != RSA_NO_PADDING)
        return -1;

    int ret = get_sig_from_man(from, flen, to, len,
                               get_rsa_padding_name(padding));
    return (ret == len) ? ret : -1;
}

/*
 * Entry point: detects key type and dispatches to the RSA path.
 * EVP_PKEY_EC would go to a separate branch - but there is no
 * EVP_PKEY_PQC branch, because no such path exists.
 */
int
tls_ctx_use_management_external_key(struct tls_root_ctx *ctx)
{
    EVP_PKEY *pkey = X509_get0_pubkey(cert);

    if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA)
        tls_ctx_use_external_rsa_key(ctx, pkey);
}
