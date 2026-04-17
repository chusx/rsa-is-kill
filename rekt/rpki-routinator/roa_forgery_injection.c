/*
 * roa_forgery_injection.c
 *
 * RPKI Route Origin Authorization (ROA) forging surface once
 * an RIR trust anchor RSA key is factored. Routinator, OctoRPKI,
 * StayRTR, FORT all validate ROAs via the same chain.
 *
 * A ROA is a CMS SignedData (RFC 6488) wrapping an IP prefix +
 * origin AS binding (RFC 6482). The signed content commits to
 * (IPPrefix, MaxLength, OriginAS). The signer is an EE cert
 * chained to the RIR trust anchor (ARIN, RIPE, APNIC, AFRINIC,
 * LACNIC) — all RSA-2048.
 */

#include <stdint.h>
#include <string.h>
#include "rpki.h"

/* All five RIR trust anchors — published in
 * https://rpki.arin.net/, ripe.net/rpki, etc. */
extern const uint8_t RIR_TRUST_ANCHOR_PUB[][384];

struct roa_content {
    uint32_t  asn;                     /* origin AS                */
    uint8_t   ip_family;               /* 1 = IPv4, 2 = IPv6      */
    uint8_t   prefix[16];              /* up to /128               */
    uint8_t   prefix_len;
    uint8_t   max_len;                 /* longest announcement ok  */
};

struct roa_signed {
    struct roa_content content;
    uint8_t  ee_cert[2048]; size_t ee_cert_len;
    uint8_t  sig[256];                 /* RSA-SHA256               */
};

/* Routinator's vrp_from_roa path (rpki-rs/src/repository/roa.rs
 * in Rust, transcribed to C-struct for this repo's style). */
int routinator_validate_roa(const struct roa_signed *r,
                            int rir_index)
{
    /* Chain EE cert to the relevant RIR trust anchor. */
    if (x509_chain_verify(r->ee_cert, r->ee_cert_len,
            RIR_TRUST_ANCHOR_PUB[rir_index], 384))
        return RPKI_CHAIN;

    /* Check the cert's IP address delegation extension matches
     * the ROA content's prefix. This is the RFC 3779 resource
     * extension. A forged cert can carry ANY prefix. */
    if (!cert_rfc3779_covers(r->ee_cert, r->ee_cert_len,
            r->content.ip_family, r->content.prefix,
            r->content.prefix_len))
        return RPKI_RESOURCE;

    uint8_t h[32];
    sha256_of(&r->content, sizeof r->content, h);
    if (verify_with_cert(r->ee_cert, r->ee_cert_len,
                         h, r->sig, sizeof r->sig))
        return RPKI_SIG;

    /* Valid ROA -> emit a VRP (Validated ROA Payload) to the
     * RTR server, which pushes it to every BGP speaker on the
     * ISP's border routers. The border router then PREFERS the
     * cryptographically-validated origin over any non-validated
     * announcement. */
    return rpki_emit_vrp(r->content.asn, r->content.ip_family,
                         r->content.prefix, r->content.prefix_len,
                         r->content.max_len);
}

/* ---- Sovereign routing attack once RIR TA is factored ------
 *
 *  1. Factor (say) RIPE NCC TA RSA-2048.
 *  2. Forge an EE cert with RFC 3779 extension claiming
 *     8.8.8.0/24 (Google DNS), origin AS 174 (Cogent) or any
 *     attacker AS.
 *  3. Sign a ROA binding 8.8.8.0/24 -> AS(attacker).
 *  4. Publish in the RPKI RRDP repository (or inject via RRDP
 *     MitM — also RSA TLS, a second dependency).
 *  5. Every ISP doing ROV pulls the forged ROA into their
 *     VRP set. Their border routers now PREFER the attacker's
 *     route for 8.8.8.0/24 over Google's legitimate
 *     announcement — because the attacker's is "VALID" and
 *     Google's (if not ROA-covered) is "UNKNOWN" or "INVALID".
 *
 *  RPKI inverts safely-failed BGP into authenticated attack:
 *  without RPKI, a BGP hijack is "best path wins" and can be
 *  out-competed; with RPKI + forged ROA, the hijack is
 *  cryptographically authoritative.
 *
 *  Recovery: RIR publishes new TA; every validator rebuilds;
 *  but the old TA remains cached in thousands of RTR caches
 *  until TTL expires. RIPE NCC's TAL rotation plan: 6-12 months.
 * --------------------------------------------------------- */
