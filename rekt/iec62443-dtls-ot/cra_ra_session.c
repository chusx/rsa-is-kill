/*
 * cra_ra_session.c
 *
 * IEC 62443-3-3 SR 1.5 (Authenticator management) / CR 1.5
 * (Software process and device identification) implementation
 * as shipped by Rockwell FactoryTalk AssetCentre, Siemens
 * SIMATIC WinCC Unified, and Honeywell Experion HIVE for
 * authenticating engineer workstations to OT field devices.
 *
 * Connection is DTLS 1.2 RSA-2048 between Engineering Station
 * (EWS) and field device (PLC/DCS controller/drive). On top
 * of DTLS the device runs a CR 1.5 "software process
 * identification" handshake: EWS signs a device-issued nonce
 * with its commissioning-issued RSA identity cert, proving it
 * is the sanctioned engineering tool and not an impostor
 * running on a rogue laptop patched into the OT VLAN.
 */

#include <stdint.h>
#include <string.h>
#include "iec62443.h"

/* Per-plant issuing CA, installed during commissioning by the
 * system integrator (e.g. Rockwell Automation Services). Chains
 * up to the plant OT root in the FactoryTalk Directory. */
extern const uint8_t PLANT_OT_INTERMEDIATE_PUB[384];

enum ot_role {
    OTR_OPERATOR  = 1,                  /* HMI read, ack alarms   */
    OTR_ENGINEER  = 2,                  /* tag changes, control   */
    OTR_PROGRAMMER= 3,                  /* download logic         */
    OTR_MAINT     = 4,                  /* FW update, diagnostics */
};

struct cr15_hello {
    char      ews_hostname[64];
    char      ews_user_upn[128];        /* ad\jsmith@plant.local  */
    uint32_t  tool_version;
    uint8_t   cert[2048]; size_t cert_len;
};

struct cr15_challenge {
    uint8_t   nonce[32];
    uint64_t  device_epoch;             /* IED boot counter       */
    char      device_tag[32];           /* "PLC-EU-PROD-07"       */
};

struct cr15_response {
    uint8_t   nonce[32];                /* echoed                 */
    uint64_t  device_epoch;
    enum ot_role requested_role;
    uint64_t  lease_seconds;            /* max ~8 h ops shift     */
    uint8_t   sig[256];                 /* RSA over TBS fields    */
};

int cr15_device_accept(const struct cr15_hello *h,
                       const struct cr15_challenge *ch_out,
                       const struct cr15_response *rsp,
                       struct ot_session *s)
{
    /* 1. Chain EWS cert to plant intermediate. */
    if (x509_chain_verify(h->cert, h->cert_len,
                          PLANT_OT_INTERMEDIATE_PUB,
                          sizeof PLANT_OT_INTERMEDIATE_PUB))
        return OT_DENY_CHAIN;

    /* 2. Cert extension 1.3.6.1.4.1.48658.62443.1 carries the
     * maximum OT role for this tool/user. */
    enum ot_role max;
    if (cert_extract_ot_role(h->cert, h->cert_len, &max))
        return OT_DENY_ROLE_EXT;
    if (rsp->requested_role > max) return OT_DENY_ROLE_ESCALATE;

    /* 3. Verify nonce-binding signature. */
    if (memcmp(rsp->nonce, ch_out->nonce, 32)) return OT_DENY_NONCE;
    if (rsp->device_epoch != ch_out->device_epoch) return OT_DENY_EPOCH;

    uint8_t tbs[32+8+4+8];
    memcpy(tbs, rsp->nonce, 32);
    write_be64(tbs+32, rsp->device_epoch);
    write_be32(tbs+40, rsp->requested_role);
    write_be64(tbs+44, rsp->lease_seconds);
    uint8_t h256[32]; sha256(tbs, sizeof tbs, h256);
    if (verify_with_cert(h->cert, h->cert_len,
                         h256, rsp->sig, 256))
        return OT_DENY_SIG;

    s->role = rsp->requested_role;
    s->lease_until = now() + rsp->lease_seconds;
    strncpy(s->operator_upn, h->ews_user_upn, sizeof s->operator_upn);
    audit_log("cr15_accept",
              h->ews_user_upn, ch_out->device_tag, s->role);
    return OT_ACCEPT;
}

/* =========================================================
 *  Authenticated control-action dispatch. Only OTR_ENGINEER+
 *  can call rockwell_download_logic; only OTR_MAINT can call
 *  device_firmware_update. Every call re-checks the session.
 * ========================================================= */

int rockwell_download_logic(struct ot_session *s,
                            const void *l5k, size_t len)
{
    if (s->role < OTR_PROGRAMMER) return OT_DENY_ROLE;
    if (now() > s->lease_until)   return OT_LEASE_EXPIRED;
    return cip_download_ladder(l5k, len);
}

int device_firmware_update(struct ot_session *s,
                           const void *fw, size_t fw_len,
                           const uint8_t *oem_sig, size_t sig_len)
{
    if (s->role < OTR_MAINT) return OT_DENY_ROLE;
    /* Firmware ALSO signed by vendor root (different RSA key,
     * see vendor-specific example dirs). That's a second
     * RSA dependency in the same kill-chain. */
    return firmware_verify_and_stage(fw, fw_len, oem_sig, sig_len);
}

/* ---- Attack once PLANT_OT_INTERMEDIATE_PUB is factored ----
 * Issue a cert with role=OTR_PROGRAMMER for any EWS hostname;
 * DTLS + CR 1.5 both accept it. Attacker downloads arbitrary
 * ladder logic to every PLC on the plant OT VLAN. Because
 * plant intermediates are shared across sites for a given
 * integrator template, factoring one can yield fleet-wide
 * access across multiple customer installations.
 * --------------------------------------------------------- */
