/*
 * fix_session_logon.c
 *
 * FIX (Financial Information eXchange) session logon with
 * RSA-signed session authentication as used by CME Globex,
 * ICE, LSEG / Turquoise, Eurex, and most electronic
 * exchange matching engines.
 *
 * FIX 4.2/4.4/5.0 SP2 (FIXT 1.1): the Logon(35=A) message
 * carries an RSA-signed token (CME iLink 3 uses a
 * HMAC-SHA256 variant, but many venues still use RSA via
 * FIXS / TLS-with-RSA-client-cert). The cert's Subject DN
 * maps to a firm's CompID + trader authorization.
 *
 * A factored firm RSA key allows an attacker to impersonate
 * any authorized trader and submit orders on the exchange.
 */

#include <stdint.h>
#include <string.h>
#include "fix.h"

extern const uint8_t EXCHANGE_TLS_ROOT_PUB[384];

struct fix_logon {
    char       sender_comp_id[16];     /* "GSCO", "JPMS", "MSFX" */
    char       target_comp_id[16];     /* "CME", "ICE"            */
    uint32_t   msg_seq_num;
    uint64_t   sending_time;           /* UTC nanos               */
    uint32_t   heartbeat_int;
    uint8_t    client_cert[2048]; size_t client_cert_len;
    uint8_t    sig[384];               /* RSA-SHA256 over logon   */
};

int exchange_accept_logon(const struct fix_logon *l)
{
    /* Chain firm cert to exchange PKI. */
    if (x509_chain_verify(l->client_cert, l->client_cert_len,
            EXCHANGE_TLS_ROOT_PUB, sizeof EXCHANGE_TLS_ROOT_PUB))
        return FIX_CHAIN;

    /* Cert SAN must match SenderCompID. */
    if (!cert_matches_compid(l->client_cert, l->client_cert_len,
                             l->sender_comp_id))
        return FIX_COMPID;

    uint8_t h[32];
    sha256_of(l, offsetof(struct fix_logon, client_cert), h);
    if (verify_with_cert(l->client_cert, l->client_cert_len,
                         h, l->sig, sizeof l->sig))
        return FIX_SIG;

    /* Session established; all subsequent NewOrderSingle(35=D),
     * OrderCancelRequest(35=F), etc. flow over this session.
     * The exchange's risk engine enforces position limits per
     * CompID, but the crypto is the identity gate. */
    return fix_session_activate(l->sender_comp_id,
                                l->msg_seq_num);
}

/* ---- Market manipulation surface --------------------------
 *  Firm RSA key factored:
 *    Impersonate any trading firm. Submit massive directional
 *    orders (spoofing at machine speed); flash crash a
 *    single-name equity, futures contract, or options chain.
 *    The exchange attributes the activity to the victim firm's
 *    CompID; forensic attribution requires out-of-band IP/
 *    network analysis.
 *
 *  Exchange TLS root factored:
 *    MitM the FIX session between firm and exchange: modify
 *    orders in-flight (price, size, side) or selectively drop
 *    cancels. Front-running at the network layer. Applicable
 *    to every participant on that exchange.
 *
 *  Recovery: exchange rotates PKI; every member firm re-
 *  enrolls. CME has ~300 clearing firms and ~3000 executing
 *  firms; coordinated rekey measured in weeks during which
 *  alternative auth (IP-restrict + password) is degraded.
 * --------------------------------------------------------- */
