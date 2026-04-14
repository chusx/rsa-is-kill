/*
 * Source: ISC BIND9 - https://github.com/isc-projects/bind9
 * File:   lib/dns/opensslrsa_link.c
 * License: MPL-2.0
 *
 * Relevant excerpt: RSA zone signing for DNSSEC.
 *
 * DNSSEC uses RSA to sign every DNS record set (RRset) in a signed zone.
 * The signed root zone, all TLDs (.com, .net, .org, etc.), and the
 * majority of signed second-level domains use RSA keys.  The root KSK
 * (Key Signing Key) is RSA-2048.  Most TLD ZSKs are RSA-2048 or RSA-1024.
 *
 * If RSA is broken:
 *   - Every DNSSEC-signed response can be forged
 *   - DANE (certificate pinning in DNS) collapses - the cert you pin IS
 *     the cert attackers now forge
 *   - DKIM public keys in DNS are forgeable (see opendkim sample)
 *   - SPF/DMARC records can be replaced
 *   - Essentially the entire chain of DNS-based trust evaporates
 *
 * The root KSK is rotated every few years.  At the speed of RPKI/DNSSEC
 * committee processes, a PQC KSK rollover would take a decade to deploy.
 */

/*
 * RSA algorithm variant selection - this is the switch statement in BIND9
 * that maps DNSSEC algorithm numbers to hash algorithms for RSA signing.
 * Algorithm numbers are defined in IANA's DNSSEC Algorithm Numbers registry.
 */
static isc_result_t
opensslrsa_sign(dst_context_t *dctx, isc_buffer_t *sig)
{
    const EVP_MD *type = NULL;

    /* Select hash algorithm based on DNSSEC algorithm number.
     * All three cases use RSA as the signature primitive. */
    switch (dctx->key->key_alg) {
    case DST_ALG_RSASHA1:        /* Algorithm 5  - RSA/SHA-1 */
    case DST_ALG_NSEC3RSASHA1:   /* Algorithm 7  - RSA/SHA-1 for NSEC3 */
        type = isc__crypto_sha1;
        break;
    case DST_ALG_RSASHA256:      /* Algorithm 8  - RSA/SHA-256 (most common) */
    case DST_ALG_RSASHA256PRIVATEOID:
        type = isc__crypto_sha256;
        break;
    case DST_ALG_RSASHA512:      /* Algorithm 10 - RSA/SHA-512 */
    case DST_ALG_RSASHA512PRIVATEOID:
        type = isc__crypto_sha512;
        break;
    /* Note: Algorithm 13 = ECDSA P-256/SHA-256, Algorithm 15 = Ed25519
     * These are handled in separate files (opensslecdsa_link.c etc.)
     * No ML-DSA algorithm number has been assigned by IANA yet. */
    }

    /* Sign with RSA using selected hash - EVP_SignFinal calls RSA_sign() */
    if (!EVP_SignFinal(evp_md_ctx, r.base, &siglen, pkey)) {
        return dst__openssl_toresult3(dctx->category,
                                      "EVP_SignFinal", ISC_R_FAILURE);
    }
    isc_buffer_add(sig, siglen);
    return ISC_R_SUCCESS;
}

/*
 * RSA key generation for DNSSEC.
 * Standard public exponent 65537 (F4) per IETF recommendations.
 * Key size is operator-configured (typically 1024 or 2048 bits for ZSK,
 * 2048 or 4096 for KSK).  RSA-1024 ZSKs are still in production use
 * across many zones despite being deprecated.
 */
static isc_result_t
opensslrsa_generate(dst_key_t *key, int exp, void *callback)
{
    BIGNUM *e = BN_new();
    /* Set exponent to 65537 (bit 0 and bit 16 = 0x10001) */
    BN_set_bit(e, 0);
    BN_set_bit(e, 16);

    /* Generate RSA key of key->key_size bits */
    ret = opensslrsa_generate_pkey(key->key_size, key->label, e,
                                   callback, &pkey);
    return (ret);
}
