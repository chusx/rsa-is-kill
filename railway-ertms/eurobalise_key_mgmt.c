/*
 * eurobalise_key_mgmt.c
 *
 * ERTMS/ETCS (European Rail Traffic Management System) key
 * management for Eurobalise and Euroradio (GSM-R / FRMCS)
 * channels. ERTMS Level 2/3 relies on authenticated movement
 * authorities (MA) from the RBC (Radio Block Centre) to the
 * on-board EVC (European Vital Computer). The authentication
 * is 3DES-CBC-MAC with a session key; the session key is
 * RSA-2048 key-transported during RBC-EVC handshake.
 *
 * Spec: ERA SUBSET-037 v3.2, SUBSET-026 §3.5 (crypto)
 * Vendors: Alstom (Thales) ATLAS, Siemens Trainguard,
 *          Hitachi Rail, CAF Signalling, AZD Praha
 */

#include <stdint.h>
#include <string.h>
#include "ertms.h"

extern const uint8_t RBC_RSA_PUB[256];            /* RSA-2048   */
extern const uint8_t ERA_ERTMS_ROOT_PUB[384];     /* PKI anchor */

/* SUBSET-037 §5.4: session establishment. The EVC and RBC
 * exchange nonces + RBC sends its RSA-2048 cert, EVC verifies
 * and encrypts a session key under RBC pubkey. */
struct session_init {
    uint32_t  nid_rbc;                  /* RBC identifier          */
    uint32_t  nid_engine;              /* on-board unit ID        */
    uint8_t   nonce_evc[16];
    uint8_t   nonce_rbc[16];
    uint8_t   rbc_cert[2048]; size_t rbc_cert_len;
    uint8_t   encrypted_sk[256];       /* RSA-OAEP(session_key)   */
};

int evc_establish_session(const struct session_init *s,
                          struct ertms_session *sess)
{
    /* Chain RBC cert to ERA root. */
    if (x509_chain_verify(s->rbc_cert, s->rbc_cert_len,
            ERA_ERTMS_ROOT_PUB, sizeof ERA_ERTMS_ROOT_PUB))
        return ERTMS_CHAIN;

    /* Generate 3DES session key, RSA-OAEP wrap to RBC. */
    uint8_t sk[24]; csprng(sk, 24);
    rsa_oaep_encrypt(
        s->rbc_cert + cert_pk_offset(s->rbc_cert), 256,
        (uint8_t[]){1,0,1}, 3,
        sk, 24,
        (uint8_t *)s->encrypted_sk, &(size_t){256});

    /* Install session key into on-board crypto module. */
    memcpy(sess->session_key, sk, 24);
    sess->nid_rbc = s->nid_rbc;
    sess->active = 1;
    return ERTMS_OK;
}

/* Movement Authority message (SUBSET-026 §7.4.6). The RBC
 * grants the EVC permission to proceed up to a specific
 * end-of-authority (EoA) balise-group. */
struct movement_authority {
    uint32_t  nid_rbc;
    uint32_t  nid_engine;
    uint32_t  nid_ma;                   /* MA serial               */
    uint32_t  d_mamode;                /* mode profile            */
    float     v_mamode_kmh;            /* max speed under MA      */
    uint32_t  eoa_balise_group;        /* end of authority         */
    float     eoa_distance_m;
    uint32_t  t_mar_s;                 /* MA removal timer        */
    uint8_t   mac[8];                  /* 3DES-CBC-MAC (truncated)*/
};

int evc_accept_ma(const struct ertms_session *sess,
                  const struct movement_authority *ma)
{
    if (!sess->active || ma->nid_rbc != sess->nid_rbc)
        return ERTMS_SESSION;
    if (ma->nid_ma <= evc_last_ma()) return ERTMS_REPLAY;

    /* MAC verify using session key. */
    uint8_t computed[8];
    des3_cbc_mac(sess->session_key,
                 ma, offsetof(struct movement_authority, mac),
                 computed);
    if (memcmp(computed, ma->mac, 8)) return ERTMS_MAC;

    evc_install_ma(ma);
    return ERTMS_OK;
}

/* ---- Train collision surface once ERA_ERTMS_ROOT factored --
 *  - Forge an RBC cert; EVC accepts the session. The attacker
 *    now issues movement authorities to any train.
 *  - Issue conflicting MAs to two trains on the same track
 *    section -> head-on collision. The EVC trusts the MA
 *    because the crypto validated.
 *  - Issue MA with v_mamode = 300 km/h approaching a
 *    speed-restricted curve -> derailment.
 *  - Revoke MA mid-section (t_mar_s = 0): emergency braking
 *    cascade across a corridor -> passenger injury + network
 *    disruption.
 *
 *  Recovery: ERA mandate to rotate ERTMS PKI; every RBC and
 *  EVC across the EU rail network (30+ infrastructure managers,
 *  thousands of trains) needs new keys. ERTMS re-commissioning
 *  requires track possession + test runs per EN 50129 SIL-4;
 *  measured in years.
 * --------------------------------------------------------- */
