/*
 * libgcrypt_rsa.c
 *
 * GNU Libgcrypt — RSA implementation.
 * Repository: git.gnupg.org (GNU project)
 * Source: https://git.gnupg.org/cgi-bin/gitweb.cgi?p=libgcrypt.git;a=blob;f=cipher/rsa.c
 *
 * Libgcrypt is the cryptographic library used by:
 *   - GnuPG (the canonical implementation — gpg, gpgsm, gpg-agent)
 *   - systemd (journal signing, cryptsetup key derivation)
 *   - GNOME Keyring / libsecret
 *   - KDE Wallet (kwallet5)
 *   - Glib / libglib (used by hundreds of GNOME apps)
 *   - gnutls (via libgcrypt for some operations)
 *   - Libgcrypt is FIPS 140-2 validated (cert #2616) — so it's in government Linux
 *
 * Libgcrypt uses S-expression (sexp) format for all key material.
 * An RSA private key S-expression looks like:
 *   (private-key (rsa (n #00...) (e #010001#) (d #...) (p #...) (q #...) (u #...)))
 *
 * The gcry_pk_sign() / gcry_pk_verify() / gcry_pk_encrypt() functions
 * are the public API. Under the hood, rsa_sign() / rsa_verify() etc.
 * call mpi_powm() for modular exponentiation.
 */

#include <gcrypt.h>

/*
 * rsa_generate() — generate an RSA keypair.
 * Source: libgcrypt cipher/rsa.c generate()
 *
 * Returns the private key as an S-expression. The public key is
 * extracted with gcry_pk_get_public_sexp().
 */
static gcry_err_code_t
rsa_generate(gcry_sexp_t *r_key, unsigned int nbits, unsigned long evalue,
             gcry_sexp_t genparms, gcry_sexp_t *r_extrainfo)
{
    gpg_err_code_t ec;
    RSA_secret_key sk;

    /* nbits: 1024, 2048, 3072, 4096 — no ML-DSA key size makes sense here */
    /* evalue: typically 65537 (F4) */

    ec = generate_fips (&sk, nbits, evalue, r_extrainfo);
    if (!ec) {
        *r_key = sexp_encode_private_rsa_key (&sk);
        /* Key sexp: (private-key (rsa (n ...) (e ...) (d ...) (p ...) (q ...) (u ...))) */
    }

    _gcry_mpi_release (sk.n); _gcry_mpi_release (sk.e);
    _gcry_mpi_release (sk.d); _gcry_mpi_release (sk.p);
    _gcry_mpi_release (sk.q); _gcry_mpi_release (sk.u);
    return ec;
}

/*
 * rsa_sign() — RSA PKCS#1 v1.5 or PSS signing.
 * Source: libgcrypt cipher/rsa.c rsa_sign()
 *
 * Called by gcry_pk_sign() when key algorithm is GCRY_PK_RSA.
 * Input:  s-expression (data (value #...# )) + private key sexp
 * Output: s-expression (sig-val (rsa (s #...# )))
 */
static gcry_err_code_t
rsa_sign(gcry_sexp_t *r_sig, gcry_sexp_t s_data, gcry_sexp_t keyparms)
{
    gcry_err_code_t rc;
    struct pk_encoding_ctx ctx;
    gcry_mpi_t data = NULL;
    RSA_secret_key sk = {NULL, NULL, NULL, NULL, NULL, NULL};
    gcry_mpi_t sig = NULL;

    _gcry_pk_util_init_encoding_ctx (&ctx, PUBKEY_OP_SIGN,
                                     rsa_get_nbits (keyparms));

    /* Extract data from s-expression; apply EMSA-PKCS1-v1.5 or PSS padding */
    rc = _gcry_pk_util_data_to_mpi (s_data, &data, &ctx);
    if (rc) goto leave;

    /* Extract RSA private key components from keyparms sexp */
    rc = sexp_to_rsa_key (keyparms, &sk, /*want_private=*/1);
    if (rc) goto leave;

    /* RSA private key operation: sig = data ^ d mod n */
    /* Uses CRT: sig = CRT(data ^ d_p mod p, data ^ d_q mod q) */
    secret (sig, data, &sk);

    /* Encode result */
    rc = gcry_sexp_build (r_sig, NULL, "(sig-val(rsa(s%M)))", sig);

leave:
    _gcry_mpi_release (data);
    _gcry_mpi_release (sig);
    _gcry_mpi_release (sk.n); _gcry_mpi_release (sk.e);
    _gcry_mpi_release (sk.d); _gcry_mpi_release (sk.p);
    _gcry_mpi_release (sk.q); _gcry_mpi_release (sk.u);
    _gcry_pk_util_free_encoding_ctx (&ctx);
    return rc;
}

/*
 * rsa_verify() — RSA signature verification.
 * Source: libgcrypt cipher/rsa.c rsa_verify()
 */
static gcry_err_code_t
rsa_verify(gcry_sexp_t s_sig, gcry_sexp_t s_data, gcry_sexp_t keyparms)
{
    gcry_err_code_t rc;
    struct pk_encoding_ctx ctx;
    gcry_mpi_t sig = NULL, data = NULL;
    RSA_public_key pk = {NULL, NULL};
    gcry_mpi_t result = NULL;
    gcry_mpi_t decoded = NULL;

    /* Extract sig from (sig-val (rsa (s #...#))) */
    /* Extract data from (data (value #...#)) */
    /* Extract public key: (public-key (rsa (n ...) (e ...))) */

    sexp_to_rsa_key (keyparms, (RSA_secret_key*)&pk, /*want_private=*/0);

    /* RSA public key operation: result = sig ^ e mod n */
    _gcry_mpi_powm (result, sig, pk.e, pk.n);

    /* Compare with expected encoded message digest */
    if (_gcry_mpi_cmp (result, data) != 0)
        rc = GPG_ERR_BAD_SIGNATURE;
    else
        rc = 0;

    _gcry_mpi_release (result);
    _gcry_mpi_release (sig);
    _gcry_mpi_release (data);
    _gcry_mpi_release (pk.n);
    _gcry_mpi_release (pk.e);
    _gcry_pk_util_free_encoding_ctx (&ctx);
    return rc;
}

/*
 * Public API usage example — how GnuPG calls libgcrypt RSA:
 *
 * From gnupg/g10/pubkey-enc.c — decrypting an RSA-encrypted session key:
 */
int
gnupg_decrypt_session_key_rsa(PKT_pubkey_enc *enc, DEK *dek,
                               gcry_sexp_t sk_sexp)
{
    gcry_sexp_t s_data = NULL;
    gcry_sexp_t s_plain = NULL;
    int rc;

    /* Build data S-expression from encrypted session key */
    rc = gcry_sexp_build (&s_data, NULL,
                          "(enc-val(flags pkcs1)(rsa(a%m)))",
                          enc->data[0]);
    if (rc) return rc;

    /* gcry_pk_decrypt() routes to rsa_decrypt() in cipher/rsa.c */
    /* This computes: plain = ciphertext ^ d mod n                  */
    /* Where d is the RSA private exponent from the secret key sexp */
    rc = gcry_pk_decrypt (&s_plain, s_data, sk_sexp);

    /* Extract the decrypted AES session key from the plain sexp */
    /* ... */

    gcry_sexp_release (s_data);
    gcry_sexp_release (s_plain);
    return rc;
}

/*
 * systemd uses libgcrypt for journal signing:
 * src/journal/journal-authenticate.c (systemd repository)
 *
 *   gcry_sexp_build(&sexp, NULL,
 *     "(public-key (rsa (n %b) (e %b)))",
 *     (int)key->n_size, key->n,
 *     (int)key->e_size, key->e);
 *
 * Every systemd-journald instance on Fedora/RHEL signs journal files
 * with RSA to allow forward-secure sealing (FSS). The RSA public key
 * is stored in /var/log/journal/<machine-id>/fss.
 */
