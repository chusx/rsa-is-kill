/*
 * Source: strongSwan - https://github.com/strongswan/strongswan
 * File:   src/libstrongswan/plugins/x509/x509_cert.c
 * License: GPLv2
 *
 * Relevant excerpt: X.509 certificate signature verification used in
 * IKEv2 RSA authentication (the most common enterprise VPN auth method).
 *
 * strongSwan does have experimental PQC support via the oqs plugin
 * (liboqs), but:
 *   - It is not enabled in any distro package by default.
 *   - IKEv2 has no standardised PQC authentication method (only
 *     experimental drafts exist as of 2026).
 *   - All deployed VPN gateways use RSA certificates from corporate PKI.
 *   - A CRQC could impersonate any VPN endpoint by forging its cert.
 */

/*
 * issued_by: verify that this certificate was signed by issuer.
 * The scheme (RSA-SHA256, ECDSA-SHA384, etc.) is parsed from the
 * certificate's AlgorithmIdentifier field.  A PQC OID (e.g. ML-DSA)
 * would parse correctly only if signature_params_parse() knows it -
 * which requires liboqs and explicit build-time configuration.
 * The default build handles RSA and ECDSA only.
 */
METHOD(certificate_t, issued_by, bool,
    private_x509_cert_t *this, certificate_t *issuer,
    signature_params_t **scheme)
{
    public_key_t *key;
    bool valid;

    /* 1. Check issuer/subject name match */
    /* 2. Check basic constraints (CA flag) */
    /* ... omitted for brevity ... */

    /* 3. Get issuer's public key - type determines which plugin handles it */
    key = issuer->get_public_key(issuer);
    if (!key)
        return FALSE;

    /* 4. Cryptographic verification.
     *    this->scheme->scheme is an enum like SIGN_RSA_EMSA_PKCS1_SHA256.
     *    For RSA, the rsa plugin handles it.
     *    For a PQC cert, a corresponding plugin must be loaded - and the
     *    IKEv2 RFC for PQC auth (draft-ietf-ipsecme-ikev2-pqc-auth) is
     *    still a draft as of 2026.
     */
    valid = key->verify(key,
                        this->scheme->scheme,   /* e.g. SIGN_RSA_EMSA_PKCS1_SHA256 */
                        this->scheme->params,
                        this->tbsCertificate,   /* DER-encoded TBSCertificate */
                        this->signature);       /* RSA signature bytes */
    key->destroy(key);

    if (valid && scheme)
        *scheme = signature_params_clone(this->scheme);
    return valid;
}

/*
 * ASN.1 parsing entry point - maps OID to internal scheme enum.
 * Currently knows: RSA+SHA{1,256,384,512}, ECDSA+SHA{256,384,512},
 * Ed25519, Ed448.  No ML-DSA OIDs in the default build.
 */
static bool
parse_certificate(private_x509_cert_t *this)
{
    /* ... */
    case X509_OBJ_SIG_ALG:
        if (!signature_params_parse(object, level, &sig_alg))
            goto end;
        /* sig_alg.scheme will be SIGN_UNKNOWN for any PQC OID
           unless the oqs plugin is loaded */
        break;
    /* ... */
}
