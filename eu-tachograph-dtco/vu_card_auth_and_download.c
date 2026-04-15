/*
 * vu_card_auth_and_download.c
 *
 * EU smart tachograph (Gen2v2, with Gen1 backward compat).
 * Vehicle-Unit side: driver card insertion, mutual auth, activity
 * recording, signed .ddd download, DSRC roadside beacon emission.
 * Chain: ERCA → MSCA → Card/VU certificates.
 */

#include <stdint.h>
#include <string.h>
#include "vu.h"
#include "rsa_pkcs1v15.h"

extern const uint8_t ERCA_GEN1_PUB[256];  /* RSA-2048 in Gen1 appendix 11 */


/* =========================================================
 *  1. Driver-card insertion (Gen1 — RSA path)
 * ========================================================= */

struct gen1_card_cert {
    uint8_t   cert_body[194];         /* ISO 7816-8 card cert */
    uint8_t   ca_cert[194];           /* MSCA cert signed by ERCA */
};

int vu_authenticate_driver_card_gen1(const struct gen1_card_cert *c,
                                     uint8_t card_pub_out[128])
{
    /* ERCA → MSCA */
    uint8_t msca_pub[128];
    if (rsa_recover_plain_gen1(ERCA_GEN1_PUB, sizeof ERCA_GEN1_PUB,
                               c->ca_cert, sizeof c->ca_cert,
                               msca_pub, sizeof msca_pub) != 0)
        return ERR_MSCA;

    /* MSCA → Card */
    if (rsa_recover_plain_gen1(msca_pub, sizeof msca_pub,
                               c->cert_body, sizeof c->cert_body,
                               card_pub_out, 128) != 0)
        return ERR_CARD;

    /* Challenge-response with recovered card pub */
    uint8_t challenge[8], rsp[128];
    rand_bytes(challenge, 8);
    if (card_internal_authenticate(challenge, rsp) != 0)
        return ERR_CARD_IO;
    if (rsa_verify_iso9796_2(card_pub_out, 128,
                             challenge, 8, rsp, 128) != 0)
        return ERR_CARD_AUTH;
    return 0;
}


/* =========================================================
 *  2. Activity recording — per-minute slot
 * ========================================================= */

enum activity { ACT_BREAK = 0, ACT_AVAIL = 1, ACT_WORK = 2, ACT_DRIVE = 3 };

struct activity_slot {
    uint32_t  minute_utc;
    uint8_t   act;                    /* enum activity */
    uint8_t   crew;                   /* single / team */
    int32_t   lat_1e6, lon_1e6;       /* Gen2: per-location entry */
    uint32_t  odometer_km;
};

void vu_record_minute(struct activity_slot *s)
{
    s->minute_utc = utc_minute();
    s->act        = infer_activity();
    s->odometer_km = read_odometer();
    gnss_position(&s->lat_1e6, &s->lon_1e6);
    ring_append(ACT_RING, s, sizeof *s);
}


/* =========================================================
 *  3. .ddd download with VU signature (evidentiary)
 * ========================================================= */

struct ddd_download {
    char      vin[17];
    char      vu_serial[16];
    uint32_t  gen_from, gen_to;       /* period boundaries */
    uint32_t  n_slots;
    struct activity_slot *slots;      /* pointer to streamed body */
    uint8_t   vu_cert[194];
    uint8_t   sig[128];               /* RSA-1024 in Gen1; PSS in Gen2 */
};

int vu_emit_signed_download(struct ddd_download *d)
{
    /* Hash the body; slots is streamed through the hash chain */
    uint8_t h[20];                    /* SHA-1 per Gen1 appendix 11 */
    sha1_init();
    sha1_update(d, offsetof(struct ddd_download, slots));
    stream_slots_into_sha1(d->gen_from, d->gen_to, &d->n_slots);
    sha1_final(h);

    return rsa_sign_iso9796_2(VU_SIGNING_KEY, h, 20, d->sig, 128);
}


/* =========================================================
 *  4. DSRC 5.8 GHz roadside remote early-detection
 *
 *  Every ~60 s broadcast a signed summary so patrolling vehicles
 *  can read it without stopping the truck. Gen2 mandatory.
 * ========================================================= */

struct dsrc_beacon {
    char      vin[17];
    uint32_t  ts;
    uint16_t  speed_kmh_x10;
    uint32_t  drive_today_s;
    uint32_t  drive_week_s;
    uint8_t   flags;                  /* open-drawer, power-loss, etc */
    uint8_t   sig[128];
};

void vu_broadcast_dsrc(struct dsrc_beacon *b)
{
    b->ts = utc_seconds();
    populate_compliance_counters(b);

    uint8_t h[32];
    sha256_of(b, offsetof(struct dsrc_beacon, sig), h);
    rsa_pkcs1v15_sign_sha256(VU_SIGNING_KEY, h, 32, b->sig, 128);
    dsrc_tx(b, sizeof *b);
}


/* ---- Breakage ---------------------------------------------
 *
 *  ERCA root factored:
 *    - Forged MSCAs → forged cards EU-wide. "Phantom rested
 *      driver" cards bypass 561/2006 driving-hour limits.
 *    - Forged VU certs → counterfeit VUs pass workshop pairing.
 *
 *  MSCA factored:
 *    - Member-state-scope card cloning; fleets in that country
 *      can rotate identical "rested" cards without detection.
 *
 *  VU per-unit key factored:
 *    - Downloaded .ddd files no longer evidentiary in drivers'-
 *      hours prosecutions — defence challenges signature provenance.
 *    - DSRC beacons spoofed to mis-state compliance at roadside.
 */
