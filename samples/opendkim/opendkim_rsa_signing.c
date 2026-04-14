/*
 * Source: OpenDKIM - https://github.com/trusteddomainproject/OpenDKIM
 * File:   opendkim/opendkim.c
 * License: BSD-3-Clause / Sendmail Open Source License
 *
 * Relevant excerpt: DKIM signing algorithm selection.
 * DKIM (RFC 6376) authenticates outbound email by signing message headers
 * with the domain's private key.  The public key is published in DNS.
 * OpenDKIM's entire signing table maps human-readable names to RSA
 * algorithm constants - there is no PQC option.
 *
 * The problem is systemic: even if OpenDKIM added ML-DSA support,
 * DKIM verifiers (every receiving MTA in the world) would need to
 * support it too before a sending domain could safely use it.
 * No PQC DKIM RFC has been published.  Every email sent today with
 * DKIM is signed with RSA and that signature will be forgeable on a CRQC.
 */

/*
 * dkimf_sign[]: complete lookup table of supported signing algorithms.
 * RSA-SHA1 and RSA-SHA256 are the only options.
 * No Ed25519-SHA256 (added in RFC 8463) support in this table.
 * No ML-DSA entry exists or is planned.
 */
struct lookup dkimf_sign[] =
{
    { "rsa-sha1",   DKIM_SIGN_RSASHA1   },
    { "rsa-sha256", DKIM_SIGN_RSASHA256 },
    { NULL,         -1                  },
};

/*
 * Configuration structure fields relevant to signing algorithm.
 * conf_signalg is set from the config file (default: rsa-sha256).
 * There is no runtime negotiation - one algorithm per milter instance.
 */
struct dkimf_config {
    /* ... */
    dkim_alg_t  conf_signalg;       /* signing algorithm (rsa-sha1 or rsa-sha256) */
    char       *conf_signalgstr;    /* string form of the above */
    /* ... */
};

/*
 * Per-message context - algorithm is copied from global config at
 * message start.  No per-recipient or per-domain algorithm agility.
 */
struct msgctx {
    /* ... */
    dkim_alg_t  mctx_signalg;       /* algorithm for this message */
    /* ... */
};

/*
 * Assignment: every outbound message gets the configured (RSA) algorithm.
 */
void dkimf_sign_message(struct dkimf_config *conf, struct msgctx *dfc)
{
    dfc->mctx_signalg = conf->conf_signalg;  /* always RSA-SHA1 or RSA-SHA256 */
}
