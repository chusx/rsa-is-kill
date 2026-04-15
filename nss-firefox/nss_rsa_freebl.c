/*
 * nss_rsa_freebl.c
 *
 * Mozilla NSS (Network Security Services) — RSA implementation in freebl.
 * Repository: hg.mozilla.org (Mercurial)
 * Source: https://hg.mozilla.org/mozilla-central/file/tip/security/nss/lib/freebl/rsa.c
 *
 * NSS is Mozilla's cryptographic library, used by:
 *   - Firefox (1.5 billion installs)
 *   - Thunderbird
 *   - Red Hat Enterprise Linux / Fedora / CentOS (system SSL via nss-tools)
 *   - LibreOffice (document signatures)
 *   - Pidgin, Epiphany, and dozens of GNOME/GTK applications
 *   - Java on Linux via PKCS#11 NSS bridge
 *   - Chromium on Linux historically (before switching to BoringSSL)
 *
 * NSS is the system cryptography library for a huge fraction of the
 * Linux desktop and server ecosystem. The /etc/pki/ directory on RHEL/CentOS/Fedora
 * is an NSS database. The system trust anchors (root CAs) are stored in NSS format.
 *
 * NSS freebl RSA operations use Montgomery multiplication for modular exponentiation.
 * The RSA private key operations use CRT (Chinese Remainder Theorem) for performance:
 *   d_p = d mod (p-1), d_q = d mod (q-1), q_inv = q^-1 mod p
 *
 * NSS has experimental ML-KEM support (added 2024) but RSA is still the primary
 * algorithm for TLS client and server authentication. No ML-DSA in NSS.
 */

#include "blapi.h"
#include "secerr.h"
#include "prerror.h"
#include "mpi.h"

/*
 * RSA_PrivateKeyOp() — raw RSA private key operation (CRT form).
 *
 * Called for:
 *   - TLS server: signing CertificateVerify or ServerKeyExchange
 *   - TLS client: decrypting RSA key exchange (TLS 1.2 and earlier)
 *   - PKCS#1 signature generation (document signing, email signing)
 *
 * Source: nss/lib/freebl/rsa.c RSA_PrivateKeyOp()
 */
SECStatus
RSA_PrivateKeyOp(RSAPrivateKey *key,  /* RSA-2048 or RSA-4096 private key */
                 unsigned char *output,
                 const unsigned char *input)
{
    SECStatus rv = SECSuccess;
    mp_int p, q, d_p, d_q, qInv;
    mp_int m, m1, m2, h, tmp;

    MP_DIGITS(&p)    = 0;
    MP_DIGITS(&q)    = 0;
    MP_DIGITS(&d_p)  = 0;
    MP_DIGITS(&d_q)  = 0;
    MP_DIGITS(&qInv) = 0;
    MP_DIGITS(&m)    = 0;

    /* Load the CRT private key components */
    SECITEM_TO_MPINT(key->prime1, &p);   /* p: first RSA prime */
    SECITEM_TO_MPINT(key->prime2, &q);   /* q: second RSA prime */
    SECITEM_TO_MPINT(key->exponent1, &d_p);  /* d mod (p-1) */
    SECITEM_TO_MPINT(key->exponent2, &d_q);  /* d mod (q-1) */
    SECITEM_TO_MPINT(key->coefficient, &qInv); /* q^-1 mod p */
    SECITEM_TO_MPINT_REV(input, key->modulus.len, &m);

    /* CRT: m1 = m^d_p mod p */
    mp_exptmod(&m, &d_p, &p, &m1);

    /* CRT: m2 = m^d_q mod q */
    mp_exptmod(&m, &d_q, &q, &m2);

    /* Combine: h = qInv * (m1 - m2) mod p */
    mp_sub(&m1, &m2, &h);
    mp_mulmod(&h, &qInv, &p, &h);

    /* result = m2 + h * q */
    mp_mul(&h, &q, &tmp);
    mp_add(&m2, &tmp, &m1);

    /* Serialize result into output buffer */
    mp_to_fixlen_octets(&m1, output, key->modulus.len);

    mp_clear(&p); mp_clear(&q); mp_clear(&d_p);
    mp_clear(&d_q); mp_clear(&qInv); mp_clear(&m);
    mp_clear(&m1); mp_clear(&m2); mp_clear(&h); mp_clear(&tmp);
    return rv;
}

/*
 * RSA_PublicKeyOp() — raw RSA public key operation.
 * Called for: signature verification, PKCS#1 v1.5 verification.
 * Source: nss/lib/freebl/rsa.c RSA_PublicKeyOp()
 */
SECStatus
RSA_PublicKeyOp(RSAPublicKey *key,   /* n=modulus, e=65537 typically */
                unsigned char *output,
                const unsigned char *input)
{
    mp_int n, e, m, c;
    SECStatus rv = SECSuccess;

    SECITEM_TO_MPINT(key->modulus,        &n);  /* n: RSA modulus */
    SECITEM_TO_MPINT(key->publicExponent, &e);  /* e: 65537 = F4 */
    SECITEM_TO_MPINT_REV(input, key->modulus.len, &c);

    /* c = m^e mod n  — the "easy" direction, fast with e=65537 */
    mp_exptmod(&c, &e, &n, &m);

    mp_to_fixlen_octets(&m, output, key->modulus.len);

    mp_clear(&n); mp_clear(&e); mp_clear(&m); mp_clear(&c);
    return rv;
}

/*
 * RSA_PrivateKeyOpDoubleChecked() — side-channel hardened variant.
 *
 * Uses RSA blinding (randomized) to prevent timing/power attacks.
 * Called by NSS TLS for all server-side RSA operations.
 *
 * Source: nss/lib/freebl/rsa.c RSA_PrivateKeyOpDoubleChecked()
 * The "double checked" name: it recomputes and verifies the result.
 */
SECStatus
RSA_PrivateKeyOpDoubleChecked(RSAPrivateKey *key,
                               unsigned char *output,
                               const unsigned char *input)
{
    SECStatus rv;
    unsigned char check[MAX_RSA_MODULUS_LEN];

    /* Perform the private key operation with blinding */
    rv = rsa_blinding_op(key, output, input, PR_TRUE);
    if (rv != SECSuccess) return rv;

    /* Verify: public_key_op(output) must equal input */
    /* This catches CRT fault attacks (Bellcore attack) */
    rv = RSA_PublicKeyOp((RSAPublicKey*)key, check, output);
    if (rv != SECSuccess) return rv;

    if (PORT_Memcmp(check, input, key->modulus.len) != 0) {
        PORT_SetError(SEC_ERROR_LIBRARY_FAILURE);
        return SECFailure;
    }

    return SECSuccess;
}

/*
 * RSAPrivateKey and RSAPublicKey structures.
 * Source: nss/lib/freebl/blapi.h
 *
 * These are populated from PKCS#8 private key files (.key, .p8),
 * PKCS#12 (.p12) keystores, and NSS key databases (/etc/pki/nssdb/).
 */
struct RSAPrivateKeyStr {
    PLArenaPool *arena;
    SECItem version;
    SECItem modulus;           /* n = p * q  (e.g. 256 bytes for RSA-2048) */
    SECItem publicExponent;    /* e = 65537 */
    SECItem privateExponent;   /* d = e^-1 mod (p-1)(q-1) */
    SECItem prime1;            /* p */
    SECItem prime2;            /* q */
    SECItem exponent1;         /* d mod (p-1) */
    SECItem exponent2;         /* d mod (q-1) */
    SECItem coefficient;       /* q^-1 mod p */
};

/*
 * System-level NSS database on RHEL/CentOS/Fedora:
 *
 * /etc/pki/nssdb/   — system-wide NSS trust store
 *   cert9.db        — certificate database (SQLite3)
 *   key4.db         — private key database (SQLite3)
 *   pkcs11.txt      — PKCS#11 module configuration
 *
 * The system NSS database stores:
 *   - Root CA trust anchors (RSA-2048/4096 roots)
 *   - TLS client certificates (RSA-2048 by default in certutil)
 *   - Private keys for those certificates
 *
 * certutil -g -s "CN=test" -n mykey -d /etc/pki/nssdb
 * creates an RSA-2048 key by default (no PQC option exists in certutil).
 *
 * On RHEL 9, the entire system crypto is NSS-backed.
 * Every TLS connection from system tools (curl, wget, yum, dnf, subscription-manager)
 * goes through NSS and uses RSA-based verification.
 */
