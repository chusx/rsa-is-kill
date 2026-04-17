/*
 * cap_alert_signing.c
 *
 * FEMA Integrated Public Alert and Warning System (IPAWS)
 * Common Alerting Protocol (CAP, OASIS CAP v1.2) alert
 * signing. Every Wireless Emergency Alert (WEA), Emergency
 * Alert System (EAS), and NOAA Weather Alert distributed
 * through IPAWS is XML-signed with the originating agency's
 * RSA certificate, chained to the IPAWS CA.
 *
 * Alert types: AMBER, tsunami, tornado, nuclear/radiological,
 * HAZMAT, active shooter, presidential alert (per 47 USC §151).
 */

#include <stdint.h>
#include <string.h>
#include "cap.h"

extern const uint8_t IPAWS_CA_ROOT_PUB[384];

struct cap_alert {
    char       identifier[64];
    char       sender[64];             /* "w-nws.webmaster@..."   */
    char       sent[24];               /* ISO 8601                */
    char       status[16];             /* "Actual"                */
    char       msg_type[16];           /* "Alert" / "Cancel"      */
    char       scope[16];              /* "Public"                */
    char       event[64];              /* "Tornado Warning"       */
    char       urgency[16];
    char       severity[16];
    char       certainty[16];
    char       area_desc[256];
    char       polygon[1024];          /* geo-polygon             */
    char       geocode_same[32];       /* FIPS code               */
    uint8_t    sender_cert[2048]; size_t sender_cert_len;
    uint8_t    xmldsig[384];
};

int ipaws_gateway_accept(const struct cap_alert *a)
{
    if (x509_chain_verify(a->sender_cert, a->sender_cert_len,
            IPAWS_CA_ROOT_PUB, sizeof IPAWS_CA_ROOT_PUB))
        return CAP_CHAIN;

    uint8_t h[32];
    cap_canonical_hash(a, h);
    if (verify_with_cert(a->sender_cert, a->sender_cert_len,
                         h, a->xmldsig, sizeof a->xmldsig))
        return CAP_SIG;

    /* Distribute to EAS encoder/decoder systems (Sage Digital
     * ENDEC, Monroe Dasdec) and cell-broadcast gateways (WEA). */
    return ipaws_distribute(a);
}

/* ---- Mass-panic / false-alert surface ---------------------
 *  IPAWS CA root factored:
 *    Forge a "Ballistic Missile Warning" or "Nuclear Detonation"
 *    CAP alert with status=Actual, severity=Extreme. IPAWS
 *    distributes to every EAS broadcaster and WEA-capable cell
 *    tower in the polygon. Hawaii 2018 missile-alert was a
 *    human-error single click; this is cryptographically
 *    authenticated at IPAWS level. Panic, highway accidents,
 *    cardiac events.
 *  Recovery: FEMA rotates IPAWS PKI; every ENDEC and WEA
 *  gateway updated. ~50k EAS participants + every carrier.
 * --------------------------------------------------------- */
