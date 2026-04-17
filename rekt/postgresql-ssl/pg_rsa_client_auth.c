/*
 * pg_rsa_client_auth.c
 *
 * PostgreSQL RSA client certificate authentication (hostssl + cert auth).
 * Repository: git.postgresql.org
 * Source: https://git.postgresql.org/gitweb/?p=postgresql.git;a=blob;f=src/interfaces/libpq/fe-secure-openssl.c
 *         https://git.postgresql.org/gitweb/?p=postgresql.git;a=blob;f=src/backend/libpq/be-secure-openssl.c
 *
 * PostgreSQL supports client certificate authentication via the "cert" auth method
 * in pg_hba.conf. This is used in environments that require strong authentication:
 *   - Financial databases (payment processing, banking data)
 *   - Healthcare databases (HIPAA-regulated patient data)
 *   - Government databases (FedRAMP, FISMA compliance)
 *   - Kubernetes PostgreSQL (cert auth for pod-to-database connections)
 *   - Multi-tenant SaaS (per-tenant certificates for database isolation)
 *
 * The connection requires:
 *   - Server certificate (RSA-2048, validated by client)
 *   - Client certificate (RSA-2048, validated by server — proves user identity)
 *
 * Certificate CN maps to PostgreSQL username (or arbitrary mapping with clientcert=dn).
 * The RSA client certificate IS the credential — no password needed.
 *
 * Also: PostgreSQL uses libssl for all hostssl connections (encrypted data in transit).
 * TLS session uses RSA for server authentication in non-ECDHE cipher suites.
 */

#include "postgres.h"
#include "libpq/libpq.h"
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/err.h>

/*
 * be_tls_open_server() — server-side TLS initialization.
 * Source: src/backend/libpq/be-secure-openssl.c be_tls_open_server()
 *
 * Loads the PostgreSQL server's RSA certificate and private key.
 * Sets up client certificate verification (for cert auth).
 */
int
be_tls_open_server(Port *port)
{
    int r;
    SSL *ssl;
    X509 *client_cert = NULL;

    ssl = SSL_new(SSL_context);
    port->ssl = ssl;

    /*
     * Load server RSA certificate and private key.
     * Default location: $PGDATA/server.crt and $PGDATA/server.key
     * Created by: openssl req -new -x509 -days 365 -nodes \
     *               -out server.crt -keyout server.key -newkey rsa:2048
     *   (RSA-2048 is the default; no PQC option in pg's ssl setup docs)
     */
    if (SSL_use_certificate_file(ssl, ssl_cert_file, SSL_FILETYPE_PEM) != 1) {
        ereport(COMMERROR,
                (errcode(ERRCODE_CONFIG_FILE_ERROR),
                 errmsg("could not load server certificate file \"%s\"",
                        ssl_cert_file)));
        return -1;
    }

    if (SSL_use_PrivateKey_file(ssl, ssl_key_file, SSL_FILETYPE_PEM) != 1) {
        ereport(COMMERROR,
                (errcode(ERRCODE_CONFIG_FILE_ERROR),
                 errmsg("could not load private key file \"%s\"",
                        ssl_key_file)));
        return -1;
    }

    /*
     * Client certificate verification.
     * SSL_VERIFY_PEER: request client certificate.
     * SSL_VERIFY_FAIL_IF_NO_PEER_CERT: require it (for cert auth method).
     *
     * The client presents an RSA-2048 certificate. PostgreSQL extracts the
     * CN and uses it as the PostgreSQL username (or the full DN with clientcert=dn).
     *
     * A CRQC can forge any client certificate with any CN. pg_hba.conf says
     * "hostssl mydb myuser 10.0.0.0/8 cert" — present a cert with CN=myuser
     * and you're in, no password, no other factor.
     */
    if (ssl_ca_file[0]) {
        SSL_set_verify(ssl,
                       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       verify_cb);
    }

    r = SSL_accept(ssl);
    if (r <= 0) {
        ereport(COMMERROR,
                (errcode(ERRCODE_PROTOCOL_VIOLATION),
                 errmsg("could not accept SSL connection: %s",
                        SSLerrmessage(ERR_get_error()))));
        return -1;
    }

    /* Extract and store the client certificate */
    client_cert = SSL_get_peer_certificate(ssl);
    if (client_cert) {
        /* CN from the certificate becomes the PostgreSQL username */
        port->peer_cn = X509_NAME_oneline(
            X509_get_subject_name(client_cert), NULL, 0);
        X509_free(client_cert);
    }

    return 0;
}

/*
 * pgtls_get_peer_certificate_hash() — gets the TLS channel binding token.
 * Source: src/interfaces/libpq/fe-secure-openssl.c
 *
 * Used for "tls-server-end-point" channel binding in SCRAM-SHA-256-PLUS.
 * The binding includes the hash of the server's certificate.
 * Server certificate is RSA-2048; its hash is used for channel binding.
 */
char *
pgtls_get_peer_certificate_hash(PGconn *conn, size_t *len, char **errMsg)
{
    X509 *peer_cert;
    const EVP_MD *algo_type;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_size;
    char *ret = NULL;

    peer_cert = SSL_get_peer_certificate(conn->ssl);
    if (!peer_cert) return NULL;

    /* Get the signature algorithm of the server's RSA certificate */
    switch (X509_get_signature_nid(peer_cert)) {
        case NID_md5WithRSAEncryption:      /* broken, but seen in legacy deployments */
        case NID_sha1WithRSAEncryption:     /* deprecated but still common */
            algo_type = EVP_sha256();       /* upgrade to SHA-256 per RFC 5929 */
            break;
        case NID_sha256WithRSAEncryption:
        case NID_sha384WithRSAEncryption:
        case NID_sha512WithRSAEncryption:
            algo_type = EVP_sha256();
            break;
        default:
            *errMsg = "unsupported certificate type for channel binding";
            goto error;
    }

    if (!X509_digest(peer_cert, algo_type, hash, &hash_size))
        goto error;

    ret = malloc(hash_size);
    memcpy(ret, hash, hash_size);
    *len = hash_size;

error:
    X509_free(peer_cert);
    return ret;
}

/*
 * pg_hba.conf configuration for RSA client certificate authentication:
 *
 * # Require SSL + client cert for all connections to the payments database
 * # The certificate CN must match the database username
 * hostssl  payments  paymentapp  10.0.0.0/8  cert  clientcert=verify-full
 *
 * # Superuser access only via certificate from the DBA team's CA
 * hostssl  all  postgres  127.0.0.1/32  cert  clientcert=verify-ca
 *
 * Affected deployments:
 *   - Amazon RDS for PostgreSQL: "Require SSL" + "ssl_cert" auth
 *   - Azure Database for PostgreSQL: same
 *   - Google Cloud SQL for PostgreSQL: ssl_mode=verify-full
 *   - Kubernetes: cert-manager issues RSA-2048 certs for pod-to-db TLS
 *
 * In FedRAMP/FISMA compliant deployments, RSA client certificate auth
 * is often required by security policy. The certificate IS the access control.
 */
