/*
 * iec61850_mms_assoc.c
 *
 * IEC 61850 MMS association establishment over IEC 62351-4 with
 * client/server X.509 RSA certificates. This is the layer that
 * a SCADA/HMI (GE Grid Solutions, ABB MicroSCADA, Siemens
 * SICAM PAS, Schneider EcoStruxure) uses to open a control
 * session to an IED (protection relay, merging unit, bay
 * controller) in a transmission substation.
 *
 * Under the session:
 *   - Read/Write of Logical Nodes (CSWI, XCBR, PTRC, MMXU...)
 *   - SelectBeforeOperate + Operate on controllable points
 *     (e.g. XCBR1.Pos = open -> open the 400 kV breaker)
 *   - File transfer of COMTRADE disturbance records
 *   - SBO-with-enhanced-security signed commands (62351-4)
 *
 * The RSA cert authenticates the peer during TLS handshake and
 * is ALSO used to sign control commands at the 62351-4 app
 * layer (belt-and-braces; the command carries a signature even
 * within the TLS channel so repository logs can audit later).
 */

#include <stdint.h>
#include <string.h>
#include "mms.h"
#include "iec62351.h"

/* Utility-assigned CA (e.g. "TenneT Substation PKI", "National
 * Grid OT Root", "ENEL Critical Infrastructure CA"). One CA per
 * transmission operator; thousands of IEDs per utility; hundreds
 * of utilities worldwide. All RSA-2048, X.509. */
extern const uint8_t UTILITY_OT_ROOT_PUB[384];

struct mms_associate_req {
    uint8_t   called_ap_title[32];      /* IED logical device ID */
    uint8_t   calling_ap_title[32];     /* HMI ID                */
    uint16_t  max_pdu_size;             /* negotiated            */
    uint8_t   mms_version;              /* 1 = 2003 edition      */
    /* --- 62351-4 extension: peer cert + signed nonce -------- */
    uint8_t   peer_cert[2048];          /* RSA-2048 X.509 DER    */
    size_t    peer_cert_len;
    uint8_t   nonce[32];
    uint8_t   nonce_sig[256];           /* RSA-PKCS1v15-SHA256   */
};

int mms_accept_associate(const struct mms_associate_req *r,
                         struct mms_session *s)
{
    /* (1) TLS channel is already up; the peer cert presented
     * here MUST match the TLS cert SPKI — channel binding.
     * This prevents a TLS-intermediary from presenting a
     * different identity at the app layer. */
    if (tls_peer_spki_matches(r->peer_cert, r->peer_cert_len))
        return MMS_REJECT_CHANNEL_BINDING;

    /* (2) Chain cert to the utility OT root. Some utilities
     * issue a per-bay intermediate; at minimum 2 levels. */
    if (x509_chain_verify(r->peer_cert, r->peer_cert_len,
                          UTILITY_OT_ROOT_PUB,
                          sizeof UTILITY_OT_ROOT_PUB))
        return MMS_REJECT_CHAIN;

    /* (3) Verify nonce signature; binds this association to
     * a freshly-issued challenge the IED can replay-check. */
    uint8_t h[32];
    sha256(r->nonce, 32, h);
    if (verify_with_cert(r->peer_cert, r->peer_cert_len,
                         h, r->nonce_sig, sizeof r->nonce_sig))
        return MMS_REJECT_NONCE_SIG;

    /* (4) Role extraction from cert extension 1.3.6.1.4.1.16909.1
     * (IEC 62351 role authorization). Levels:
     *   VIEWER  — read only
     *   OPERATOR— SBO + Operate on controllables
     *   ENG     — parameter-set changes
     *   INSTALL — firmware update / CID download */
    s->role = cert_extract_role(r->peer_cert, r->peer_cert_len);
    strncpy(s->peer_id, cert_subject_cn(r->peer_cert, r->peer_cert_len),
            sizeof s->peer_id);
    memcpy(s->peer_nonce, r->nonce, 32);
    return MMS_ACCEPT;
}

/* =========================================================
 *  Control command: Select Before Operate (SBO) with
 *  Enhanced Security, IEC 61850-7-2 §20.6.2.
 * ========================================================= */
struct ctrl_operate {
    char      lnref[64];                /* "BAY1/XCBR1.Pos"      */
    uint8_t   ctl_val;                  /* 0 = open, 1 = close   */
    uint32_t  origin_orcat;             /* 2 = STATION,3 = REMOTE*/
    char      origin_orident[64];       /* operator ID           */
    uint32_t  ctl_num;                  /* incrementing per LN   */
    uint64_t  t_origin;                 /* UTC µs                */
    uint8_t   test;                     /* 0 in ops, 1 in sim    */
    uint8_t   check;                    /* interlock/synchrocheck*/
    uint8_t   sig[256];                 /* RSA over above fields */
};

int mms_operate(struct mms_session *s, const struct ctrl_operate *c)
{
    if (s->role < ROLE_OPERATOR) return MMS_DENY_ROLE;

    /* Check SBO pairing: a prior Select message with the same
     * ctl_num must have completed within the IED's sbo.cfg
     * window (commonly 30 s). */
    if (!sbo_selected(s, c->lnref, c->ctl_num)) return MMS_NO_SBO;

    /* App-layer sig — binds (lnref, ctl_val, ctl_num, t_origin,
     * peer_nonce) to the session's authenticated cert. */
    uint8_t h[32];
    sha256_of_signed_fields(c, s->peer_nonce, h);
    if (verify_with_cert_by_id(s->peer_id, h, c->sig, 256))
        return MMS_DENY_SIG;

    /* Finally drive the XCBR (breaker) actuator via the
     * protection-relay output contact. This is the line
     * that opens or closes a 400 kV breaker on a bulk
     * transmission bus. */
    return xcbr_drive(c->lnref, c->ctl_val);
}

/* ---- Attack when UTILITY_OT_ROOT factored ------------------
 *   Mint an OPERATOR-role cert, association succeeds against
 *   every IED chained to that root. SBO+Operate on XCBR1.Pos
 *   across a substation opens all bays -> islanding / load
 *   shedding cascade. Simultaneous fleet action = 2015-Ukraine
 *   generalized across any transmission operator whose OT root
 *   was factored. Recovery needs a new utility OT PKI + every
 *   IED's trust store rewritten, IEC 61850 SCL re-engineering,
 *   and re-commissioning outage windows.
 * --------------------------------------------------------- */
