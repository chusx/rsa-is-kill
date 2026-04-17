/*
 * opcua_session_activate.c
 *
 * OPC UA (IEC 62541) session activation with X.509 user token
 * authentication. OPC UA is the universal ICS interoperability
 * protocol: Siemens WinCC UA, Rockwell FT Optix, Beckhoff
 * TwinCAT, ABB Ability Symphony+, Schneider EcoStruxure, B&R.
 *
 * Both the transport-layer (UA-SecureChannel) and the
 * application-layer (ActivateSession with X509IdentityToken)
 * use RSA. The server application cert is RSA-2048 by default;
 * client identity tokens are X.509 certs issued by a plant-
 * level OT CA.
 */

#include <stdint.h>
#include <string.h>
#include "opcua.h"

extern const uint8_t PLANT_OPCUA_ROOT_PUB[384];

struct activate_session_req {
    uint8_t   client_cert[2048]; size_t client_cert_len;
    uint8_t   server_nonce[32];
    uint8_t   user_identity_token[2048]; size_t uit_len;
    uint8_t   user_token_sig[256];     /* RSA-SHA256 over (cert_data || server_nonce) */
};

int opcua_activate_session(const struct activate_session_req *r,
                           struct opcua_session *s)
{
    /* (1) Transport-layer: SecureChannel already uses RSA for
     * asymmetric key exchange (OPC UA Part 6 §6.7.2). */

    /* (2) Application-layer: X509IdentityToken. */
    if (x509_chain_verify(r->user_identity_token, r->uit_len,
            PLANT_OPCUA_ROOT_PUB, sizeof PLANT_OPCUA_ROOT_PUB))
        return OPCUA_CHAIN;

    /* Token signature binds the identity token to this server
     * nonce to prevent relay. */
    uint8_t tbs[2048+32]; size_t tbs_len = r->uit_len + 32;
    memcpy(tbs, r->user_identity_token, r->uit_len);
    memcpy(tbs + r->uit_len, r->server_nonce, 32);
    uint8_t h[32]; sha256(tbs, tbs_len, h);
    if (verify_with_cert(r->user_identity_token, r->uit_len,
                         h, r->user_token_sig, 256))
        return OPCUA_SIG;

    /* Extract role from cert (OPC UA Part 6 §6.2.3). */
    s->role = cert_extract_opcua_role(r->user_identity_token, r->uit_len);
    return OPCUA_OK;
}

/* ---- OT-wide identity-takeover surface ---------------------
 *  PLANT_OPCUA_ROOT factored: forge a user identity token with
 *  SecurityAdmin role -> browse+write any node on any OPC UA
 *  server in the plant. Read process variables, write setpoints,
 *  invoke methods (StartPump, OpenValve, StopLine). OPC UA is
 *  the gateway between IT MES and OT PLC; one compromised
 *  session = plant-floor control.
 * --------------------------------------------------------- */
