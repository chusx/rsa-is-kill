/*
 * epcis_verification.c
 *
 * Drug Supply Chain Security Act (DSCSA, 21 USC §360eee)
 * serialized product verification. Every pharmaceutical unit
 * (bottle, carton, case) carries a GS1 GTIN + serial number
 * + lot + expiry encoded in a GS1 DataMatrix barcode. At each
 * hop in the supply chain (manufacturer -> 3PL -> wholesaler
 * -> pharmacy), the EPCIS (Electronic Product Code Information
 * Services) event is signed by the trading partner's RSA cert
 * and uploaded to the DSCSA-mandated verification system
 * (TraceLink, SAP ATTP, rfxcel).
 *
 * A factored trading-partner RSA key allows an attacker to
 * forge EPCIS events and introduce counterfeit drugs into the
 * legitimate supply chain with valid electronic pedigrees.
 */

#include <stdint.h>
#include <string.h>
#include "dscsa.h"

extern const uint8_t FDA_DSCSA_ROOT_PUB[384];

struct epcis_event {
    char       gtin[14];
    char       serial[20];
    char       lot[20];
    char       expiry[8];
    char       sender_gln[13];        /* GS1 location number      */
    char       receiver_gln[13];
    uint8_t    event_type;             /* SHIP, RECEIVE, VERIFY    */
    uint64_t   event_ts;
    uint8_t    sender_cert[2048]; size_t sender_cert_len;
    uint8_t    sig[384];
};

int vrs_accept_event(const struct epcis_event *e)
{
    if (x509_chain_verify(e->sender_cert, e->sender_cert_len,
            FDA_DSCSA_ROOT_PUB, sizeof FDA_DSCSA_ROOT_PUB))
        return DSCSA_CHAIN;
    uint8_t h[32];
    sha256_of(e, offsetof(struct epcis_event, sender_cert), h);
    if (verify_with_cert(e->sender_cert, e->sender_cert_len,
                         h, e->sig, sizeof e->sig))
        return DSCSA_SIG;
    return vrs_record_event(e);
}

/* ---- Counterfeit drug introduction surface -----------------
 *  Trading-partner RSA factored: forge SHIP events for
 *  non-existent or counterfeit product units with valid
 *  electronic pedigrees. Pharmacy receives "verified" product
 *  that is actually counterfeit. Patient harm from adulterated
 *  or sub-potent medication. FDA cannot distinguish from
 *  legitimate supply chain activity because the crypto is valid.
 * --------------------------------------------------------- */
