/*
 * root_ksk_forgery.c
 *
 * DNS root KSK (Key Signing Key) validation path inside a
 * DNSSEC-validating resolver. BIND 9's val_verify_rrsig()
 * chain, simplified. The root KSK is RSA-2048
 * (key tag 20326, algorithm 8 = RSASHA256).
 *
 * A factored root KSK allows an attacker to forge DNSKEY
 * RRSIGs for the root zone -> sign arbitrary DS records for
 * any TLD -> sign arbitrary DNSKEY for any TLD -> sign
 * arbitrary A/AAAA/MX/CNAME for any name on the internet.
 * Every DNSSEC-validating resolver on the planet accepts.
 */

#include <stdint.h>
#include <string.h>
#include "dns.h"

/* root-anchors.xml equivalent — the trust anchor. */
#define ROOT_KSK_TAG    20326
#define ROOT_KSK_ALG    8             /* RSASHA256              */
#define ROOT_KSK_FLAGS  0x0101        /* SEP + Zone Key         */

extern const uint8_t ROOT_KSK_DNSKEY_RDATA[];   /* 264 bytes    */
extern size_t ROOT_KSK_DNSKEY_RDATA_LEN;

/* Validate an RRSIG covering a DNSKEY RRset at "." zone. */
int validate_root_dnskey(const struct rrset *dnskey_rrset,
                          const struct rrsig *sig)
{
    if (sig->key_tag != ROOT_KSK_TAG) return DNS_NO_ANCHOR;
    if (sig->algorithm != ROOT_KSK_ALG) return DNS_BAD_ALG;

    /* Check validity window. Root KSK signatures have a 15-day
     * validity period; ZSKs sign with a different key tag. */
    if (now() < sig->inception || now() > sig->expiration)
        return DNS_EXPIRED;

    /* Canonical wire-form of the DNSKEY RRset. */
    uint8_t canon[8192]; size_t clen;
    dns_canonical(dnskey_rrset, sig, canon, &clen);

    /* RSA-SHA256 verify against the root KSK. */
    uint8_t h[32]; sha256(canon, clen, h);
    return rsa_pkcs1v15_verify_sha256(
        ROOT_KSK_DNSKEY_RDATA + 4,
        ROOT_KSK_DNSKEY_RDATA_LEN - 4,
        ROOT_KSK_DNSKEY_RDATA,  /* flags + protocol + alg */
        4, h, 32, sig->signature, sig->sig_len);
}

/* After DNSKEY validation at ".", the resolver chains DS
 * records for each TLD: .com, .org, .gov, .mil, .cn, ...
 * Every DS is in the root zone, signed by the root ZSK,
 * which was authenticated by the root KSK. */
int validate_delegation(const char *child_zone,
                         const struct rrset *ds_rrset,
                         const struct rrsig *ds_sig,
                         const struct rrset *child_dnskey_rrset)
{
    /* ds_sig validated by ZSK, which was validated by KSK. */
    int r = validate_rrsig(ds_rrset, ds_sig);
    if (r) return r;

    /* DS record commits to child's KSK hash. */
    for (int i = 0; i < ds_rrset->count; ++i) {
        uint8_t ds_hash[64];
        dns_ds_hash(child_dnskey_rrset, ds_rrset->rdata[i].alg,
                    ds_hash);
        if (memcmp(ds_hash, ds_rrset->rdata[i].digest,
                   ds_rrset->rdata[i].digest_len) == 0)
            return DNS_SECURE;
    }
    return DNS_BOGUS;
}

/* ---- Complete internet namespace hijack --------------------
 *  Root KSK factored:
 *    1. Sign a forged DNSKEY RRset at "." containing the
 *       attacker's ZSK.
 *    2. Sign forged DS records for .com/.org/.gov/...
 *    3. At each TLD, sign forged DNSKEY, then A/AAAA.
 *    4. Every DNSSEC-validating resolver resolves attacker-
 *       controlled addresses for ANY domain name.
 *    5. DANE (RFC 6698) TLSA records also forgeable, so
 *       even certificate pinning via DNS is defeated.
 *
 *  The last KSK rollover (2017-2019) took ICANN ~3 years.
 *  An emergency rollover requires coordinating with every
 *  resolver operator to install a new trust anchor; failure
 *  to do so = those resolvers fall back to SERVFAIL for all
 *  DNSSEC-signed domains or, worse, stop validating entirely.
 * --------------------------------------------------------- */
