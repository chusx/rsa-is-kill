/*
 * openldap_sasl_tls.c
 *
 * OpenLDAP TLS and SASL EXTERNAL RSA client certificate authentication.
 * Repository: git.openldap.org (not GitHub)
 * Source: https://git.openldap.org/openldap/openldap/-/blob/master/libraries/libldap/tls_o.c
 *         https://git.openldap.org/openldap/openldap/-/blob/master/servers/slapd/sasl.c
 *
 * LDAP (Lightweight Directory Access Protocol) is the directory service for:
 *   - Corporate Active Directory (Microsoft AD runs LDAP underneath)
 *   - Linux user authentication (SSSD + LDAP + Kerberos)
 *   - Unix account management (nsswitch.conf ldap)
 *   - Application authentication backends (Apache, nginx, SSH with LDAP PAM)
 *   - Kubernetes LDAP authentication (dex, oauth2-proxy with LDAP backend)
 *
 * SASL EXTERNAL is the LDAP authentication mechanism that uses a TLS client
 * certificate for identity. The DN of the certificate subject is mapped to
 * an LDAP entry. Used by:
 *   - LDAP admin tools (ldapadd, ldapmodify authenticated as "Directory Manager")
 *   - Service accounts with certificate-based LDAP authentication
 *   - Slapd replication (replication uses TLS mutual auth with RSA certs)
 *   - PAM LDAP with certificate auth on hardened Linux systems
 */

#include <ldap.h>
#include <sasl/sasl.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

/*
 * tlso_session_new() — creates a new OpenSSL TLS session for an LDAP connection.
 * Source: libldap/tls_o.c tlso_session_new()
 *
 * The TLS session uses RSA-2048 client and server certificates.
 * The server certificate authenticates slapd to the LDAP client.
 * The client certificate (SASL EXTERNAL) authenticates the client to slapd.
 */
static tls_session *
tlso_session_new(tls_ctx *ctx, int is_server)
{
    tlso_ctx *c = (tlso_ctx *)ctx;
    tlso_session *s = LDAP_MALLOC(sizeof(*s));

    if (!s) return NULL;

    s->session = SSL_new(c->tc_ctx);
    if (!s->session) {
        LDAP_FREE(s);
        return NULL;
    }

    return (tls_session *)s;
}

/*
 * tlso_ctx_init() — initializes the OpenSSL context for LDAP TLS.
 * Source: libldap/tls_o.c tlso_ctx_init()
 *
 * Loads the LDAP server's RSA certificate and private key.
 * Configures mutual TLS (SSL_VERIFY_PEER) when SASL EXTERNAL is enabled.
 * The certificate is RSA-2048 from the enterprise CA (ADCS, or OpenLDAP CA).
 */
int
tlso_ctx_init(struct ldapoptions *lo, struct ldaptls *lt, int is_server)
{
    tlso_ctx *ctx = (tlso_ctx *)lo->ldo_tls_ctx;
    SSL_CTX *sctx = ctx->tc_ctx;

    /* Load server RSA-2048 certificate */
    if (SSL_CTX_use_certificate_file(sctx, lt->lt_certfile,
                                     SSL_FILETYPE_PEM) != 1) {
        Debug(LDAP_DEBUG_ANY, "TLS: could not use certificate `%s'.\n",
              lt->lt_certfile, 0, 0);
        return -1;
    }

    /* Load server RSA-2048 private key */
    if (SSL_CTX_use_PrivateKey_file(sctx, lt->lt_keyfile,
                                    SSL_FILETYPE_PEM) != 1) {
        Debug(LDAP_DEBUG_ANY, "TLS: could not use key file `%s'.\n",
              lt->lt_keyfile, 0, 0);
        return -1;
    }

    /* For SASL EXTERNAL: require client certificate (mutual TLS) */
    if (is_server && lo->ldo_tls_require_cert) {
        SSL_CTX_set_verify(sctx,
                           SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                           tlso_verify_cb);
        /* The client's RSA-2048 certificate subject DN is the identity for
         * SASL EXTERNAL authentication. slapd maps it to an LDAP entry via
         * the authzRegexp configuration directive. */
    }

    /* TLS cipher configuration — typical slapd deployment uses RSA ciphersuites */
    if (lt->lt_ciphersuite) {
        if (SSL_CTX_set_cipher_list(sctx, lt->lt_ciphersuite) == 0) {
            Debug(LDAP_DEBUG_ANY, "TLS: could not set cipher list `%s'.\n",
                  lt->lt_ciphersuite, 0, 0);
        }
    }

    return 0;
}

/*
 * slapd SASL EXTERNAL handler.
 * Source: slapd/sasl.c slap_sasl_external()
 *
 * When a client authenticates with SASL EXTERNAL, slapd extracts the
 * subject DN from the TLS client certificate and uses it as the identity.
 *
 * The client certificate is RSA-2048, issued by the enterprise CA.
 * The RSA public key in the cert is what a CRQC attacks.
 * With the derived private key, any client can forge a TLS client certificate
 * for any DN in the directory — and authenticate to slapd as that identity.
 */
int
slap_sasl_external(Connection *conn, slap_ssf_t ssf, struct berval *authid)
{
    int sc;
    slap_ssf_t oldssf;
    struct berval old_authid;

    /* authid.bv_val is the certificate subject DN, e.g.:
     *   "CN=Directory Manager,DC=example,DC=com"
     *   "CN=Replication User,OU=Service Accounts,DC=corp,DC=internal"
     * Whoever presents a cert with this DN is authenticated as that identity.
     *
     * With a forged TLS client cert (derived from the CA RSA key in adcs-windows/),
     * an attacker can authenticate as "cn=Directory Manager" — the LDAP superuser —
     * and read, modify, or delete any entry in the directory.
     */

    ber_dupbv(&conn->c_sasl_authz_dn, authid);
    conn->c_sasl_ssf = ssf;

    sc = slap_sasl2dn(conn, authid, &conn->c_sasl_dn, SLAP_GETDN_AUTHZID);
    return sc;
}

/*
 * slapd replication uses TLS mutual authentication between the provider
 * and consumer. The replication user's RSA certificate is in the slapd
 * configuration:
 *
 * # /etc/openldap/slapd.conf (provider)
 * TLSCACertificateFile /etc/pki/tls/certs/ca.crt
 * TLSCertificateFile   /etc/pki/tls/certs/slapd.crt    # RSA-2048
 * TLSCertificateKeyFile /etc/pki/tls/private/slapd.key  # RSA-2048 private key
 * TLSVerifyClient demand
 *
 * # syncrepl stanza on the consumer
 * syncrepl rid=001
 *   provider=ldaps://ldap01.example.com
 *   type=refreshAndPersist
 *   tls_cert=/etc/pki/tls/certs/repl.crt  # RSA-2048 replication cert
 *   tls_key=/etc/pki/tls/private/repl.key
 *   ...
 *
 * Forging the replication certificate = silently poisoning LDAP replication.
 * An attacker can inject fake LDAP entries, modify user attributes, or
 * delete accounts, and it will replicate to every slapd consumer.
 */
