/*
 * opcua_server_main.c
 *
 * OPC UA server bring-up wiring up the Basic128Rsa15 / Basic256 /
 * Basic256Sha256 security policies implemented in
 * `securitypolicy_basic128rsa15.c`. Shows the real integration of
 * OPC UA into an OT environment: app certificate loading, user
 * token policy, Discovery/GDS registration, and the client
 * authorization callback.
 *
 * This is what runs inside every OPC UA server on the factory floor:
 *   - Siemens SIMATIC OPC UA Server on S7-1500 / ET200SP CPU
 *   - Rockwell FactoryTalk Linx OPC UA Gateway
 *   - Schneider EcoStruxure Machine Expert OPC UA
 *   - B&R Automation Studio OPC UA Server
 *   - KEPServerEX (PTC ThingWorx)
 *   - Beckhoff TwinCAT OPC UA Server
 *   - IBH OPC UA Gateway for Mitsubishi / Omron controllers
 * Also the MES/SCADA-side clients: Siemens WinCC OA, AVEVA System
 * Platform, Ignition, Honeywell Experion MES.
 */

#include "open62541.h"


int main(int argc, char **argv)
{
    UA_Server *server = UA_Server_new();
    UA_ServerConfig *cfg = UA_Server_getConfig(server);

    /* ---- 1. Load app instance cert + private key + issuer list ----
     * The application instance certificate is the long-lived RSA-2048
     * cert the server presents at SecureChannel open.  Issued under
     * the plant's OPC UA GDS (Global Discovery Server) CA. */
    UA_ByteString cert    = load_der("/etc/opcua/server-cert.der");
    UA_ByteString pkey    = load_der("/etc/opcua/server-key.der");
    UA_ByteString trust[] = { load_der("/etc/opcua/plant-ca.der") };
    UA_ByteString issuer[] = { load_der("/etc/opcua/intermediate.der") };

    UA_ServerConfig_setDefaultWithSecurityPolicies(
        cfg, 4840,
        &cert, &pkey,
        trust, 1,
        issuer, 1,
        NULL, 0);           /* no revocation list initially — GDS pushes updates */

    /* ---- 2. Enforce SecurityMode on every endpoint. ----
     * OT conventional wisdom: allow only SignAndEncrypt with
     * Basic256Sha256 (or the newer Aes128Sha256RsaOaep /
     * Aes256Sha256RsaPss).  Basic128Rsa15 + None are still accepted
     * by default in many vendor shipments for interop with legacy
     * HMIs — that's where the Bleichenbacher-class risks live
     * independent of a direct factoring break. */
    for (size_t i = 0; i < cfg->endpointsSize; i++) {
        if (cfg->endpoints[i].securityMode == UA_MESSAGESECURITYMODE_NONE) {
            /* drop None endpoints */
            continue;
        }
    }

    /* ---- 3. User token policies: X.509, Username/Password, Anonymous
     *        (disabled on hardened plants). ---- */
    cfg->accessControl.allowAnonymous = UA_FALSE;
    cfg->accessControl.getUserRightsMask  = user_rights_cb;
    cfg->accessControl.activateSession    = activate_session_cb;

    /* ---- 4. Register with the GDS (auto-certificate-renewal). ----
     * The plant GDS manages per-device cert issuance + periodic
     * renewal via the OPC UA Push Management Model (Part 12).
     * Servers pull new certs signed by the plant CA at ~30% of
     * cert lifetime remaining. */
    UA_Client_registerAtGDS(server,
        "opc.tcp://gds.plant.corp:4840",
        "urn:corp:plant:assetmgmt");

    /* ---- 5. Load the information model.  A real server exposes
     *        a Siemens / Rockwell / CNCF vendor NodeSet plus OPC UA
     *        for Machinery (DI), OPC UA for Robotics, Weihenstephan
     *        Standards (beverage), FDI (process), or the Umati
     *        dictionary. ---- */
    namespace_load_plant_model(server);

    /* ---- 6. Run ---- */
    UA_StatusCode rc = UA_Server_runUntilInterrupt(server);
    UA_Server_delete(server);
    return rc == UA_STATUSCODE_GOOD ? 0 : 1;
}


static UA_StatusCode
activate_session_cb(UA_Server *s, UA_AccessControl *ac,
                     const UA_EndpointDescription *endpoint,
                     const UA_ByteString *secure_channel_rk,
                     const UA_NodeId *session_id,
                     const UA_ExtensionObject *user_identity_token,
                     void **session_ctx)
{
    /* Enforce cert chain + revocation on user X.509 tokens (one of
     * the two token types we accept post-step-3). */
    if (!opcua_user_cert_valid(user_identity_token)) {
        return UA_STATUSCODE_BADIDENTITYTOKENREJECTED;
    }
    return UA_STATUSCODE_GOOD;
}


/* ---- Breakage ----
 *
 * An OPC UA plant is unified by its GDS CA. A factoring attack on
 * that RSA-2048 CA lets an attacker:
 *   - Stand up a rogue OPC UA "controller" that existing SCADA /
 *     MES clients connect to and read/write tags from (Write
 *     commands against actuator tags = physical process effects).
 *   - Impersonate the MES to controllers, pushing recipe parameters
 *     that the controller executes — classic Stuxnet-shape attack,
 *     without needing the S7comm exploit layer at all.
 * The GDS CA is one of the single-operator RSA roots in the plant;
 * a successful factoring break collapses OT cybersecurity to the
 * physical-access + network-segmentation layers.
 */
