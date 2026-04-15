/*
 * cmu_ams_and_cpdlc.c
 *
 * Communications Management Unit (CMU) / Air Traffic Services Unit
 * (ATSU): ARINC 823 AMS-signed ACARS, FANS 1/A+ CPDLC message
 * integrity, ARINC 665 LSAP load verification. Pattern aligns
 * with Collins CMU-4000 / Honeywell MCS-7000.
 */

#include <stdint.h>
#include <string.h>
#include "cmu.h"
#include "rsa_pss.h"
#include "rsa_pkcs1v15.h"

extern const uint8_t OEM_LSAP_ROOT_PUB[384];         /* airframer */
extern const uint8_t ANSP_CPDLC_ROOT_PUB[384];       /* FAA Data Comm etc */
extern const uint8_t AIRLINE_AOC_ROOT_PUB[384];


/* =========================================================
 *  1. ARINC 823 AMS ACARS downlink signing
 * ========================================================= */

struct acars_block {
    char      tail[8];                /* N-number / reg */
    char      label[3];               /* ARINC 620 */
    char      sub_label[4];
    uint32_t  ts;
    uint16_t  body_len;
    uint8_t   body[220];              /* ACARS payload */
    uint8_t   sig[256];               /* AMS RSA-2048 */
};

int cmu_sign_acars_downlink(struct acars_block *b)
{
    uint8_t h[32];
    sha256_of(b, offsetof(struct acars_block, sig), h);
    return rsa_pss_sign_sha256_hsm(
        CMU_AMS_KEY, h, 32, b->sig, sizeof b->sig);
}


/* =========================================================
 *  2. CPDLC uplink from ANSP — verify before pilot display
 * ========================================================= */

enum cpdlc_uplink {
    UM_CLIMB_TO = 20, UM_DESCEND_TO = 23, UM_MAINTAIN = 19,
    UM_CLEARED_DIRECT_TO = 74, UM_CONTACT_FREQ = 117,
};

struct cpdlc_uplink {
    char      aircraft_id[8];
    uint32_t  msg_id;
    uint32_t  response_to;            /* downlink being replied to, or 0 */
    uint8_t   elem;                   /* UM id */
    uint8_t   params[64];             /* altitude, waypoint, freq */
    char      controller_id[12];
    uint32_t  issued_ts;
    uint8_t   ctrl_cert[1024];
    size_t    ctrl_cert_len;
    uint8_t   sig[384];
};

int cmu_ingest_cpdlc(const struct cpdlc_uplink *u)
{
    if (strncmp(u->aircraft_id, local_acid(), 8))
        return ERR_WRONG_ACID;

    if (x509_chain_verify(u->ctrl_cert, u->ctrl_cert_len,
                          ANSP_CPDLC_ROOT_PUB,
                          sizeof ANSP_CPDLC_ROOT_PUB) != 0)
        return ERR_CHAIN;

    uint8_t n[384], e[4];
    size_t n_len, e_len;
    x509_extract_pub(u->ctrl_cert, u->ctrl_cert_len,
                     n, sizeof n, &n_len, e, sizeof e, &e_len);

    uint8_t h[32];
    sha256_of(u, offsetof(struct cpdlc_uplink, sig), h);
    if (rsa_pss_verify_sha256(n, n_len, e, e_len, h, 32,
                              u->sig, sizeof u->sig) != 0)
        return ERR_SIG;

    /* Freshness: CPDLC messages with controller-timestamp > 2 min
     * old are dropped — freshness prevents replay of an earlier
     * clearance into a later phase of flight. */
    if (now_utc() - u->issued_ts > 120) return ERR_STALE;

    pilot_display_uplink(u);
    return 0;
}


/* =========================================================
 *  3. ARINC 665 LSAP load verification
 * ========================================================= */

struct lsap_header {
    char      part_number[20];        /* ARINC 665 PN */
    char      aircraft_type[8];       /* "A320", "B787", ... */
    uint32_t  version;
    uint32_t  data_len;
    uint8_t   data_sha256[32];
    uint8_t   sig[384];
};

int cmu_accept_lsap(const struct lsap_header *hdr,
                    const uint8_t *data, size_t data_len)
{
    if (data_len != hdr->data_len) return ERR_LEN;

    uint8_t h[32];
    sha256_mem(data, data_len, h);
    if (memcmp(h, hdr->data_sha256, 32)) return ERR_BODY_HASH;

    sha256_of(hdr, offsetof(struct lsap_header, sig), h);
    if (rsa_pss_verify_sha256(OEM_LSAP_ROOT_PUB,
                              sizeof OEM_LSAP_ROOT_PUB,
                              (uint8_t[]){0x01,0x00,0x01}, 3,
                              h, 32, hdr->sig, sizeof hdr->sig) != 0)
        return ERR_SIG;

    return lsap_install(hdr, data, data_len);
}


/* =========================================================
 *  4. Airline AOC dispatch release verification
 * ========================================================= */

struct dispatch_release {
    char      flight_no[8];
    char      tail[8];
    uint32_t  std_utc;
    char      dep[4], arr[4];
    float     fuel_onboard_lbs;
    float     zfw_lbs, tow_lbs, lw_lbs;
    char      dispatcher_id[8];
    char      captain_id[8];
    uint8_t   dispatcher_sig[384];
    uint8_t   captain_sig[384];       /* captain accepts */
};

int cmu_verify_dispatch(const struct dispatch_release *d)
{
    uint8_t h[32];
    sha256_of(d, offsetof(struct dispatch_release, dispatcher_sig), h);
    if (rsa_pss_verify_sha256(AIRLINE_AOC_ROOT_PUB,
                              sizeof AIRLINE_AOC_ROOT_PUB,
                              (uint8_t[]){0x01,0x00,0x01}, 3,
                              h, 32, d->dispatcher_sig,
                              sizeof d->dispatcher_sig) != 0)
        return ERR_DISP;

    /* captain_sig binds the whole structure including dispatcher
     * signature (captain's accept is over dispatcher's commit) */
    sha256_of(d, offsetof(struct dispatch_release, captain_sig), h);
    if (rsa_pss_verify_sha256(AIRLINE_AOC_ROOT_PUB,
                              sizeof AIRLINE_AOC_ROOT_PUB,
                              (uint8_t[]){0x01,0x00,0x01}, 3,
                              h, 32, d->captain_sig,
                              sizeof d->captain_sig) != 0)
        return ERR_CAPT;
    return 0;
}


/* ---- Breakage ---------------------------------------------
 *
 *  OEM LSAP root factored:
 *    - Forged nav databases / engine params accepted by
 *      aircraft. Unsafe approaches, mis-tuned engines, fleet-
 *      wide airworthiness collapse under DO-326A.
 *
 *  ANSP CPDLC root factored:
 *    - Forged controller uplinks accepted in the flight deck —
 *      altitude deviations, forged diversion clearances, or
 *      forged "cleared to land" in terminal airspace.
 *
 *  Airline AOC root factored:
 *    - Forged dispatch releases legalise undispatched flights;
 *      or genuine releases denied in favour of attacker copies.
 *
 *  Aircraft CMU AMS key factored:
 *    - Downlinked position reports unverifiable; oceanic
 *      separation assurance collapses.
 */
