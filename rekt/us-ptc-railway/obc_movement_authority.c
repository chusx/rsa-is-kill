/*
 * obc_movement_authority.c
 *
 * Onboard-Computer (OBC) receive path for PTC movement-authority
 * and switch-position messages. Pattern matches Wabtec I-ETMS
 * Train Management Computer (TMC) and Hitachi Rail STS ACSES-II
 * onboard. Runs on the locomotive's OBC — VxWorks or embedded
 * Linux on ruggedised ARM/PPC.
 *
 * Covers the crypto-authentication layer only. Braking-curve
 * enforcement, engineer-display HMI, and the 220 MHz PTC radio
 * layer are separate files.
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include "obc.h"
#include "rsa_pss.h"
#include "rsa_pkcs1v15.h"

/* AAR-operated Railroad PKI root — trust anchor for inter-carrier
 * interoperability. Each operator's issuing CA chains here. */
extern const uint8_t AAR_ITC_ROOT_PUB[512];          /* RSA-4096 */
extern const uint8_t HOME_CARRIER_CA_PUB[384];       /* this locomotive's */
extern const uint8_t OEM_OBC_FW_ROOT_PUB[512];       /* Wabtec/Hitachi */


/* =========================================================
 *  1. OBC firmware self-verify
 * ========================================================= */

struct obc_fw_manifest {
    char      product[16];
    char      build[32];
    uint32_t  rollback_idx;
    uint8_t   core_sha256[32];
    uint8_t   brake_curve_sha256[32];
    uint8_t   subdiv_data_sha256[32];     /* subdivision track database */
    uint8_t   sig[512];
};

int obc_fw_self_verify(void)
{
    struct obc_fw_manifest *m = flash_read_manifest();
    if (m->rollback_idx < hsm_rollback()) return ERR_ROLLBACK;

    uint8_t h[32];
    sha256_partition(PART_CORE, h);
    if (memcmp(h, m->core_sha256, 32)) return ERR_CORE;

    sha256_of(m, offsetof(struct obc_fw_manifest, sig), h);
    return rsa_pkcs1v15_verify_sha256(
        OEM_OBC_FW_ROOT_PUB, sizeof OEM_OBC_FW_ROOT_PUB,
        (uint8_t[]){0x01,0x00,0x01}, 3,
        h, 32, m->sig, sizeof m->sig);
}


/* =========================================================
 *  2. Movement authority — the authoritative "you may proceed"
 *
 *  A movement-authority message binds: locomotive ID, start
 *  milepost, end milepost, speed profile, validity window,
 *  monotonic authority-seq. The onboard braking-curve enforcer
 *  refuses to move past the authority limit.
 * ========================================================= */

struct movement_authority {
    char      dispatching_carrier[8];     /* "BNSF", "UP", "AMTK" */
    char      loco_initial[8];
    uint32_t  loco_number;
    uint32_t  authority_seq;              /* monotonic per loco */
    uint32_t  issued_ts;
    uint32_t  valid_until;
    uint32_t  subdivision_id;
    int32_t   start_milepost_x100;        /* signed milepost * 100 */
    int32_t   end_milepost_x100;
    uint16_t  direction;                  /* 1=INC 2=DEC */
    uint16_t  max_speed_mph;
    /* Signed speed restrictions (work zones, slow orders) can be
     * enclosed as a nested signed blob here; omitted for brevity. */
    uint8_t   dispatcher_cert[1536];
    size_t    cert_len;
    uint8_t   sig[384];
};

static uint32_t last_authority_seq;

int obc_accept_movement_authority(const struct movement_authority *ma)
{
    /* Replay guard — monotonic per locomotive. */
    if (ma->authority_seq <= last_authority_seq) return ERR_REPLAY;

    /* Locomotive scoping — authority must name us. */
    if (strncmp(ma->loco_initial, my_initial(), 8) ||
        ma->loco_number != my_number())
        return ERR_WRONG_LOCO;

    /* Time window. */
    uint32_t now = (uint32_t)time(NULL);
    if (now > ma->valid_until) return ERR_EXPIRED;

    /* Cross-carrier: chain dispatcher cert to the AAR ITC root,
     * not just our home carrier. A BNSF loco on UP track is
     * dispatched by UP and must trust UP's dispatcher-issuing CA. */
    if (x509_chain_verify(ma->dispatcher_cert, ma->cert_len,
                          AAR_ITC_ROOT_PUB,
                          sizeof AAR_ITC_ROOT_PUB) != 0)
        return ERR_CHAIN;

    uint8_t n[384], e[4];
    size_t n_len, e_len;
    x509_extract_pub(ma->dispatcher_cert, ma->cert_len,
                     n, sizeof n, &n_len, e, sizeof e, &e_len);

    uint8_t h[32];
    sha256_of(ma, offsetof(struct movement_authority, sig), h);
    if (rsa_pss_verify_sha256(n, n_len, e, e_len,
                              h, 32, ma->sig, sizeof ma->sig) != 0)
        return ERR_SIG;

    /* Plausibility: end-milepost not past the subdivision boundary;
     * max_speed not above track class limit. Defence-in-depth on
     * top of the signature. */
    if (!milepost_within_subdivision(ma->subdivision_id,
                                      ma->start_milepost_x100,
                                      ma->end_milepost_x100))
        return ERR_SUBDIV;
    if (ma->max_speed_mph > track_class_limit(ma->subdivision_id,
                                              ma->start_milepost_x100))
        return ERR_SPEED_CLASS;

    last_authority_seq = ma->authority_seq;
    install_movement_authority(ma);
    recompute_braking_curve();
    return 0;
}


/* =========================================================
 *  3. Wayside Interface Unit / switch-position message
 * ========================================================= */

struct wiu_switch_msg {
    uint32_t  wiu_id;
    uint32_t  msg_seq;
    uint32_t  ts;
    uint16_t  switch_id;
    uint8_t   position;              /* 1=NORMAL 2=REVERSE 3=UNKNOWN */
    uint8_t   circuit_healthy;
    uint8_t   wiu_cert[1024];
    size_t    cert_len;
    uint8_t   sig[384];
};

int obc_consume_wiu_switch(const struct wiu_switch_msg *w)
{
    /* WIUs are operated by the incumbent carrier at that location;
     * cert chains to the home carrier CA for home territory and
     * to AAR root for foreign-line crossings. */
    if (x509_chain_verify(w->wiu_cert, w->cert_len,
                          AAR_ITC_ROOT_PUB,
                          sizeof AAR_ITC_ROOT_PUB) != 0)
        return ERR_CHAIN;

    uint8_t n[384], e[4];
    size_t n_len, e_len;
    x509_extract_pub(w->wiu_cert, w->cert_len,
                     n, sizeof n, &n_len, e, sizeof e, &e_len);

    uint8_t h[32];
    sha256_of(w, offsetof(struct wiu_switch_msg, sig), h);
    if (rsa_pss_verify_sha256(n, n_len, e, e_len,
                              h, 32, w->sig, sizeof w->sig) != 0) {
        /* Safety default: treat unverified switch status as UNKNOWN
         * and enforce stop at the associated switch. */
        treat_switch_as_unknown(w->switch_id);
        return ERR_SIG;
    }

    if (w->position == 3 || !w->circuit_healthy) {
        treat_switch_as_unknown(w->switch_id);
    } else {
        note_switch_position(w->switch_id, w->position);
    }
    return 0;
}


/* ---- Breakage ---------------------------------------------
 *
 *   AAR_ITC_ROOT factored:
 *     - Attacker injects signed movement authorities on foreign
 *       track; onboard enforcement treats them as dispatch.
 *       Train-vs-train collision pre-conditions at track speed.
 *       This is the exact failure mode PTC exists to prevent;
 *       restoring that safety case requires rotation across
 *       every Class I + commuter + Amtrak locomotive.
 *
 *   OEM OBC fw root factored (Wabtec I-ETMS / Hitachi STS):
 *     - Signed OBC firmware that silently disables enforcement
 *       past authority limits, or mis-parses brake-curve inputs.
 *       Over-speed derailments (Frankford Junction 2015 class)
 *       no longer prevented.
 *
 *   WIU-issuing CA factored:
 *     - Signed "switch NORMAL" when actually REVERSE; trains
 *       take switches at speed into misaligned routes.
 *
 *   Railinc inter-carrier CA factored:
 *     - Dangerous-goods / hazmat-car-location integrity lost;
 *       derailment-notification EDI fabrication enables
 *       concealment of hazmat involvement in incidents.
 */
