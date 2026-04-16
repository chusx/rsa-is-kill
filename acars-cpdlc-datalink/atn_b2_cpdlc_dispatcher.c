/*
 * atn_b2_cpdlc_dispatcher.c
 *
 * ATN-B2 (Aeronautical Telecommunication Network Baseline 2)
 * CPDLC (Controller-Pilot Data Link Communication) message
 * dispatcher on the ground-side Data Link Service Provider.
 *
 * ATN-B2 adds TLS 1.2 with RSA-2048 mutual authentication
 * between the DLSP (ARINC / SITA) and the air-side CMU
 * (Collins / Honeywell). Over the authenticated channel,
 * CPDLC messages flow per ICAO Doc 9705 / DO-350A.
 *
 * CPDLC uplinks (ATC -> aircraft) are safety-critical;
 * an attacker with a factored DLSP RSA certificate can
 * MitM the ATC-pilot data link and inject forged clearances.
 * Per ICAO Annex 10 Vol III, CPDLC is the primary controller-
 * pilot comm medium in NAT (Gander/Shanwick), AFI (Roberts),
 * and soon CONUS (DataComm).
 */

#include <stdint.h>
#include <string.h>
#include "atn.h"

extern const uint8_t DLSP_TLS_ROOT_PUB[384];
extern const uint8_t AIRLINE_CMU_ROOT_PUB[384];

/* DO-350A CPDLC message element IDs (ASN.1 PER under ATN-B2) */
enum cpdlc_element {
    UM_CLIMB_TO_AND_MAINTAIN = 20,
    UM_DESCEND_TO_AND_MAINTAIN = 23,
    UM_TURN_LEFT_HEADING     = 94,
    UM_TURN_RIGHT_HEADING    = 95,
    UM_CROSS_AT_AND_MAINTAIN = 35,
    UM_CONTACT_FREQUENCY     = 117,
    UM_ROGER                 = 0,
    DM_WILCO                 = 0,
    DM_UNABLE                = 1,
    DM_STANDBY               = 2,
};

struct cpdlc_msg {
    uint32_t  msg_ref_num;              /* MRN, monotonic        */
    uint32_t  reply_to;                 /* -1 if first msg       */
    uint8_t   direction;                /* 0 = uplink, 1 = down  */
    char      acid[8];                  /* "UAL455","BAW289"     */
    char      facility_id[6];           /* "KZNY","EGGX"        */
    uint8_t   element_id;               /* UM/DM enum value      */
    union {
        struct { uint32_t fl; }                     climb;
        struct { uint32_t fl; }                     descend;
        struct { uint16_t heading; }                turn;
        struct { char fix[8]; uint32_t fl; }        cross;
        struct { uint32_t freq_khz; char id[8]; }   contact;
    } params;
    uint64_t  timestamp_utc_ns;
    /* ATN-B2 integrity wrapper (belt-and-braces over TLS) */
    uint8_t   sender_cert[2048]; size_t sender_cert_len;
    uint8_t   sig[384];
};

int dlsp_dispatch_uplink(const struct cpdlc_msg *m)
{
    /* (1) Validate the ATC facility's signing cert against the
     * DLSP root. In operational ATC, Eurocontrol / FAA issues
     * facility certs for every ARTCC/ACC. */
    if (x509_chain_verify(m->sender_cert, m->sender_cert_len,
            DLSP_TLS_ROOT_PUB, sizeof DLSP_TLS_ROOT_PUB))
        return CPDLC_AUTH_FAIL;

    uint8_t h[32];
    sha256_of(m, offsetof(struct cpdlc_msg, sender_cert), h);
    if (verify_with_cert(m->sender_cert, m->sender_cert_len,
                         h, m->sig, sizeof m->sig))
        return CPDLC_SIG_FAIL;

    /* (2) Sequencing check: MRN must be strictly increasing per
     * acid+facility pair. Replay protection. */
    if (m->msg_ref_num <= last_mrn(m->acid, m->facility_id))
        return CPDLC_REPLAY;
    mrn_bump(m->acid, m->facility_id, m->msg_ref_num);

    /* (3) MCDU / EFB renders the clearance. Safety assurance
     * relies on the pilot reading and accepting (WILCO/UNABLE);
     * but a forged "DESCEND TO AND MAINTAIN FL250" in NAT
     * MNPS can create a head-on conflict with another flight
     * level. ATC won't see a reply it didn't initiate. */
    return cmu_render_to_mcdu(m);
}

/* =========================================================
 *  FANS 1/A+ (current oceanic) uses ACARS as bearer with
 *  weaker authentication. ATN-B2 over LDACS/SATCOM with
 *  RSA TLS is the upgrade path. A factoring break collapses
 *  the entire upgrade rationale.
 * ========================================================= */

/* ---- Mid-air collision surface ----------------------------
 *  DLSP_TLS_ROOT factored:
 *    Inject UM_DESCEND_TO_AND_MAINTAIN / UM_CLIMB_TO from
 *    a fictitious facility into an aircraft's CPDLC session.
 *    Pilot reads a clearance that appears ATC-signed; if
 *    WILCO'd, the aircraft manoeuvres into conflicting
 *    traffic. TCAS RA is the last barrier but CPDLC clearance
 *    compliance historically overrides in pilot response bias.
 *    NAT / AFI sectors have minutes of radar gap.
 *  AIRLINE_CMU_ROOT factored:
 *    Forge downlink DM_WILCO from the aircraft — ATC thinks
 *    the pilot accepted; pilot never sees the message.
 *    Coordination gap leads to unresolved conflicts.
 *  Recovery: ICAO mandate to rotate DLSP PKI; every ARTCC,
 *  airline, and CMU vendor updates trust store. Multi-year
 *  program; interim = voice-only, destroying oceanic
 *  datalink capacity built over the last decade.
 * --------------------------------------------------------- */
