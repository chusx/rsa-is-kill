/*
 * Source: NTP reference implementation (ntp.org) / NTPsec
 *         https://www.ntp.org/reflib/reports/stime1/stime.pdf
 *         https://gitlab.com/NTPsec/ntpsec
 * File:   Autokey protocol (autokey.c / ssl_init.c)
 * License: NTP License (BSD-like)
 *
 * Relevant excerpt: NTP Autokey uses RSA for server authentication.
 *
 * NTP Autokey (RFC 5906) authenticates time servers using RSA signatures.
 * Time synchronization is a critical dependency of EVERY cryptographic
 * system — TLS certificate validity windows, Kerberos ticket lifetimes,
 * TOTP 2FA codes, audit log timestamps, code signing timestamps all
 * depend on the system clock being correct and authenticated.
 *
 * Attack scenario with broken RSA:
 *   1. Forge NTP Autokey RSA signature
 *   2. Serve a malicious time to any NTP client
 *   3. All TLS certificates appear expired (or not yet valid)
 *   4. Kerberos authentication breaks across the enterprise
 *   5. TOTP codes are wrong → 2FA bypassed or denied
 *   6. Certificate revocation checks use wrong time → expired CRLs trusted
 *
 * Note: NTPsec has deprecated Autokey in favor of NTS (Network Time Security,
 * RFC 8915) which uses TLS 1.3.  But NTS with TLS 1.3 still uses RSA/ECDSA
 * certificates for the initial key exchange — the PQC problem just moves
 * to the TLS layer.  Most deployed NTP infrastructure still uses Autokey.
 */

/*
 * Autokey server-side: generate a cookie signed with the server's RSA key.
 * The client verifies this with the server's public RSA key obtained from
 * a certificate exchange.  Both the certificate and the cookie signature
 * use RSA.
 */
static void
make_keys(void)
{
    EVP_PKEY *pkey;
    RSA      *rsa;

    /* Generate RSA key pair for this NTP server instance.
     * Key size: typically 512-1024 bits in legacy deployments (!).
     * The Autokey spec allows any size — many deployments use RSA-512
     * which is classically broken, let alone quantum-broken. */
    rsa = RSA_generate_key(
        512,     /* bits - yes, 512.  Many production servers use this. */
        65537,   /* public exponent */
        NULL, NULL
    );
    pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);

    /* Sign the server's Autokey value with RSA private key */
    EVP_SignInit(&ctx, EVP_md5());   /* MD5 hash - also broken classically */
    EVP_SignUpdate(&ctx, (u_char *)&autokey, len);
    EVP_SignFinal(&ctx, (u_char *)signature, &siglen, pkey);
}

/*
 * Client-side verification: check the server's RSA signature on the
 * time data.  If RSA is broken, this check passes for forged data.
 *
 * The Autokey spec was analyzed in 2012 and found to have "serious design
 * flaws" including use of 32-bit seed values and negotiable (downgradable)
 * identification schemes.  Post-quantum is the least of its problems,
 * but it is still a problem: the RSA identity anchor is forgeable.
 */
static int
crypto_verify(
    struct exten *ep,    /* extension with RSA signature */
    struct value *vp,    /* signed value */
    struct peer  *peer   /* peer state */
)
{
    EVP_PKEY     *pkey = peer->identity_key;  /* server's RSA public key */
    EVP_MD_CTX    ctx;
    int           rval;

    EVP_VerifyInit(&ctx, EVP_md5());
    EVP_VerifyUpdate(&ctx, (u_char *)vp, vp->vallen);
    rval = EVP_VerifyFinal(&ctx,
                           (u_char *)ep->pkt,  /* RSA signature bytes */
                           ntohl(ep->vallen),
                           pkey);              /* RSA public key */
    /* rval == 1: valid. A CRQC-forged signature returns 1 here. */
    return (rval);
}
