/*
 * cmts_bpi_session.c
 *
 * DOCSIS 3.1 / 4.0 CMTS (Cable Modem Termination System) side of the
 * BPI+ v2 (Baseline Privacy Interface Plus) session flow: receives
 * cable-modem Auth Request, verifies the CM's RSA-2048 device cert
 * under the DOCSIS Root CA (operated by CableLabs), returns the
 * Authorization Reply containing the RSA-wrapped Authorization Key
 * (AK), then runs periodic TEK (Traffic Encryption Key) rotation on
 * top.
 *
 * This file is the CMTS-line-card orchestration; the RSA primitives
 * it calls live in `docsis_bpi_auth.c`.
 *
 * Deployed on: Cisco cBR-8, CommScope/ARRIS E6000 + Flexible MAC
 * Architecture RPDs, Harmonic CableOS vCMTS, Vecima Entra. Every
 * major MSO (Comcast, Charter, Cox, Altice USA, Rogers, Shaw, Virgin
 * Media, Vodafone Cable, Liberty Global) runs one of these.
 */

#include <stdint.h>
#include <string.h>
#include "docsis_bpi.h"
#include "cablelabs_root.h"


struct bpi_session {
    uint8_t  cm_mac[6];
    uint8_t  cm_cert_der[2048];    size_t cm_cert_len;
    uint8_t  cm_manuf_cert_der[2048]; size_t cm_manuf_cert_len;
    uint8_t  auth_key[20];          /* AK, wrapped with CM RSA pubkey */
    uint8_t  tek[2][16];            /* active + standby TEKs (AES-128) */
    uint32_t said;                  /* Security Association ID */
    uint32_t ak_lifetime_s;
    uint32_t tek_lifetime_s;
};


/* Invoked on every Auth Info (BPKM code 12) + Auth Request (code 4)
 * pair arriving on the upstream MAC-management channel. */
int
cmts_handle_auth_request(struct bpi_session *s,
                          const uint8_t *bpkm_payload, size_t n)
{
    /* 1.  Extract CM cert + manufacturer cert + CM capabilities +
     *     signing CBC 16-byte random challenge. */
    if (bpi_parse_auth_request(bpkm_payload, n, s) != 0)
        return BPKM_REJECT_PERM_FAIL;

    /* 2.  Walk CM cert → Manufacturer CA → CableLabs DOCSIS Root CA.
     *     The DOCSIS Root CA is an RSA-2048 key held by CableLabs;
     *     manufacturer CAs under it issue per-device leaf certs at
     *     CM production time (Hitron, Technicolor, Sagemcom, ARRIS-
     *     now-CommScope, Motorola/Zoom).  Device leaf key is RSA-2048. */
    if (docsis_verify_cert_chain(
            s->cm_cert_der,      s->cm_cert_len,
            s->cm_manuf_cert_der, s->cm_manuf_cert_len,
            cablelabs_docsis_root_der) != 0)
        return BPKM_REJECT_UNAUTH;

    /* 3.  Revocation: CMTSs pull DOCSIS CRLs from CableLabs hourly. */
    if (docsis_cert_revoked(s->cm_cert_der, s->cm_cert_len))
        return BPKM_REJECT_REVOKED;

    /* 4.  Mint AK, RSA-OAEP wrap under the CM's public key, send as
     *     Auth Reply.  The AK seeds KEK derivation which in turn
     *     wraps TEKs on rotation. */
    docsis_generate_ak(s->auth_key);
    uint8_t wrapped_ak[256];
    size_t  wrapped_ak_len;
    if (docsis_rsa_oaep_wrap(
            s->cm_cert_der, s->cm_cert_len,
            s->auth_key, sizeof s->auth_key,
            wrapped_ak, &wrapped_ak_len) != 0)
        return BPKM_REJECT_PERM_FAIL;

    bpi_send_auth_reply(s, wrapped_ak, wrapped_ak_len);

    /* 5.  Prime TEKs + schedule TEK-M1/M2/M3 rekey timers. */
    docsis_seed_tek(s, 0);
    docsis_seed_tek(s, 1);
    bpi_schedule_tek_rekey(s);
    return 0;
}


/* Called every s->tek_lifetime_s/2 seconds.  Standby TEK is wrapped
 * under the KEK (which is itself derived from the AK over AES-CMAC)
 * and sent in a TEK Reply.  Modem installs, then the CMTS toggles the
 * SAID's active-TEK index. */
void
cmts_tek_rekey(struct bpi_session *s)
{
    uint8_t wrapped_tek[24];
    docsis_kek_wrap_tek(s, s->tek[1], wrapped_tek);
    bpi_send_tek_reply(s, wrapped_tek);
    docsis_seed_tek(s, 0);        /* next round's standby */
}


/* An RSA break lets an attacker (a) forge DOCSIS device certs at will
 * and bring rogue modems online under arbitrary MAC identities,
 * bypassing service-theft controls across every MSO's plant;
 * (b) impersonate CMTSs to modems and capture wrapped AKs, recovering
 * every subscriber's traffic keys; (c) forge CableLabs-root-signed
 * manufacturer-CA certs and bootstrap counterfeit modem product
 * lines. The CableLabs DOCSIS Root CA is one of the handful of
 * single-point-of-failure RSA keys that underpin most of North
 * American broadband access. */
