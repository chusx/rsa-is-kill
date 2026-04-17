/*
 * cyrus_tls_rsa.c
 *
 * Cyrus IMAP server — RSA in IMAP/POP3/SMTP TLS authentication.
 * Repository: https://github.com/cyrusimap/cyrus-imapd
 *             (also distributed via cyrusimap.org and package repos)
 * Source: imap/tls.c — tls_init_serverengine() and tls_start_servertls()
 *
 * Cyrus IMAP is the email server used by:
 *   - Carnegie Mellon University (where it was created)
 *   - Apple iCloud mail infrastructure (historically)
 *   - Fastmail (in its earlier architecture)
 *   - Hundreds of universities and research institutions worldwide
 *   - Many ISPs and managed email hosting providers
 *   - Kolab (the open-source groupware suite used by German government agencies)
 *
 * Kolab is particularly notable: it is the email solution for the German Federal
 * Government (Bundeswehr, several ministries), recommended by the BSI (German
 * Federal Office for Information Security) as an alternative to Microsoft Exchange.
 * Kolab bundles Cyrus IMAP. Cyrus uses OpenSSL for TLS.
 *
 * TLS in Cyrus IMAP protects:
 *   - IMAP STARTTLS / IMAPS (port 993): mail access
 *   - POP3S (port 995): legacy mail access
 *   - SMTP submission TLS (Postfix + Cyrus SASL + Cyrus IMAP backend)
 *   - LMTP (mail delivery from MTA to Cyrus mailbox)
 *   - Replication TLS between Cyrus IMAP servers (sync_client)
 *
 * The Cyrus IMAP TLS certificate is RSA-2048 by default.
 * Client certificates (for SASL EXTERNAL over IMAP TLS) are also RSA-2048.
 */

#include <config.h>
#include "tls.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

/* Global SSL context for the Cyrus IMAP server */
static SSL_CTX *tls_ctx = NULL;

/*
 * tls_init_serverengine() — initializes the Cyrus IMAP TLS context.
 * Source: imap/tls.c tls_init_serverengine()
 *
 * Called once at server startup. Loads the server's RSA-2048 certificate
 * and private key. Configures the cipher list.
 *
 * Configuration options (imapd.conf):
 *   tls_cert_file: /etc/ssl/certs/cyrus.crt   # RSA-2048 PEM
 *   tls_key_file:  /etc/ssl/private/cyrus.key  # RSA-2048 private key
 *   tls_ca_file:   /etc/ssl/certs/ca.crt
 *   tls_cipher_list: HIGH:!aNULL:!MD5           # includes RSA cipher suites
 */
int
tls_init_serverengine(const char *ident,
                      int verifydepth,
                      int askcert,       /* 1 = request client cert (SASL EXTERNAL) */
                      int requirecert)
{
    int off = 0;
    int verify_flags = SSL_VERIFY_NONE;
    const char *cipher_list;
    const char *CAfile;
    const char *s_cert_file;
    const char *s_key_file;

    /* Create TLS context */
    tls_ctx = SSL_CTX_new(TLS_server_method());
    if (tls_ctx == NULL) {
        syslog(LOG_ERR, "TLS server engine: cannot allocate handle");
        return -1;
    }

    /* Disable old protocols */
    SSL_CTX_set_options(tls_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                                 SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

    /* Load RSA-2048 server certificate */
    s_cert_file = config_getstring(IMAPOPT_TLS_CERT_FILE);
    if (SSL_CTX_use_certificate_chain_file(tls_ctx, s_cert_file) <= 0) {
        syslog(LOG_ERR, "TLS server engine: cannot load cert chain %s",
               s_cert_file);
        SSL_CTX_free(tls_ctx);
        return -1;
    }

    /* Load RSA-2048 private key */
    s_key_file = config_getstring(IMAPOPT_TLS_KEY_FILE);
    if (SSL_CTX_use_PrivateKey_file(tls_ctx, s_key_file, SSL_FILETYPE_PEM) <= 0) {
        syslog(LOG_ERR, "TLS server engine: cannot load private key %s",
               s_key_file);
        SSL_CTX_free(tls_ctx);
        return -1;
    }

    /* Verify the key matches the certificate */
    if (!SSL_CTX_check_private_key(tls_ctx)) {
        syslog(LOG_ERR, "TLS server engine: private key mismatch");
        SSL_CTX_free(tls_ctx);
        return -1;
    }

    /* Set cipher list — HIGH includes all RSA ciphers, no PQC options */
    cipher_list = config_getstring(IMAPOPT_TLS_CIPHER_LIST);
    if (!cipher_list) cipher_list = "HIGH:!aNULL:!MD5:@STRENGTH";
    if (SSL_CTX_set_cipher_list(tls_ctx, cipher_list) == 0) {
        syslog(LOG_ERR, "TLS server engine: cannot set cipher list");
        return -1;
    }

    /* Client certificate verification for SASL EXTERNAL */
    if (askcert) {
        verify_flags = SSL_VERIFY_PEER;
        if (requirecert)
            verify_flags |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        SSL_CTX_set_verify(tls_ctx, verify_flags, verify_callback);
        SSL_CTX_set_verify_depth(tls_ctx, verifydepth);
    }

    return 0;
}

/*
 * tls_start_servertls() — starts TLS on an established IMAP connection.
 * Source: imap/tls.c tls_start_servertls()
 *
 * Called when the client sends STARTTLS (or for direct IMAPS connections).
 * The TLS handshake authenticates the server with its RSA-2048 certificate.
 * The client verifies the server cert against its CA trust store.
 *
 * If SASL EXTERNAL is configured, the client also presents an RSA-2048
 * certificate. The certificate subject is used as the SASL identity.
 */
int
tls_start_servertls(int readfd, int writefd, int timeout,
                    int *layer, char **authid, SSL **ret)
{
    int sts;
    SSL *tls_conn;
    X509 *peer = NULL;

    /* Create SSL connection object using the server context */
    tls_conn = SSL_new(tls_ctx);
    if (tls_conn == NULL) {
        syslog(LOG_ERR, "Could not allocate 'con' with SSL_new()");
        return -1;
    }

    SSL_set_fd(tls_conn, readfd);

    /* TLS handshake — server presents RSA-2048 certificate to client */
    sts = SSL_accept(tls_conn);
    if (sts <= 0) {
        syslog(LOG_ERR, "TLS_accept error %d: %s", sts,
               ERR_reason_error_string(ERR_get_error()));
        SSL_free(tls_conn);
        return -1;
    }

    /* If SASL EXTERNAL requested, extract client certificate identity */
    if (authid) {
        peer = SSL_get_peer_certificate(tls_conn);
        if (peer) {
            /* Extract CN or subjectAltName from the client's RSA-2048 cert */
            *authid = tls_peer_CN(peer);
            X509_free(peer);
        }
    }

    /* Report cipher suite negotiated (will be an RSA ciphersuite) */
    syslog(LOG_DEBUG, "TLS: cipher=%s bits=%d",
           SSL_get_cipher(tls_conn),
           SSL_get_cipher_bits(tls_conn, NULL));

    *ret = tls_conn;
    return 0;
}

/*
 * Kolab / German government context:
 *
 * Kolab Groups Suite is the open-source groupware recommended by the German
 * BSI (Bundesamt für Sicherheit in der Informationstechnik) as an alternative
 * to Microsoft Exchange. It is used by:
 *   - German Federal Ministries (several)
 *   - Bundeswehr (German military) internal email
 *   - Swiss Federal Administration
 *   - Various EU institutions
 *
 * Kolab bundles Cyrus IMAP as its mail storage backend. Every Cyrus IMAP
 * server in a Kolab deployment has an RSA-2048 TLS certificate for IMAPS.
 *
 * An attacker who factors the Cyrus server's RSA-2048 certificate can
 * MitM IMAP connections to that server, reading and modifying email in
 * transit for all users on that Cyrus IMAP instance.
 *
 * For government Kolab deployments, that means intercepting ministerial
 * email, cabinet communications, or military internal correspondence.
 */
