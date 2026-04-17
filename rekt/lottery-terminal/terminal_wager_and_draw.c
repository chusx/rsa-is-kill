/*
 * terminal_wager_and_draw.c
 *
 * Retailer lottery terminal: signed wager submission, signed
 * validation-response, signed draw-result ingestion. Pattern
 * matches IGT Altura / Scientific Games WAVE / Intralot Photon.
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include "terminal.h"
#include "rsa_pss.h"

extern const uint8_t OPERATOR_CENTRAL_PUB[384];     /* state / national op */
extern const uint8_t MUSL_DRAW_PUB[384];            /* PowerBall / EuroMillions */
extern const uint8_t REG_GAME_APPROVAL_PUB[384];    /* gaming commission */


/* =========================================================
 *  1. Wager capture → signed submission
 * ========================================================= */

struct wager {
    char      terminal_id[12];        /* assigned by operator */
    char      retailer_id[12];
    uint64_t  seq;                    /* monotonic per terminal */
    uint32_t  issued_ts;
    char      game_code[8];           /* "PB", "MM", "EM", ... */
    uint8_t   n_plays;
    uint8_t   plays[10][12];          /* picks, per-game encoded */
    uint32_t  wager_cents;
    uint32_t  draws;                  /* # of draws the ticket covers */
    uint8_t   sig[256];               /* terminal's RSA-2048 PSS */
};

int terminal_submit_wager(struct wager *w)
{
    w->issued_ts = (uint32_t)time(NULL);
    w->seq = next_seq();

    uint8_t h[32];
    sha256_of(w, offsetof(struct wager, sig), h);
    if (rsa_pss_sign_sha256_se(TERMINAL_KEY, h, 32,
                               w->sig, sizeof w->sig) != 0)
        return ERR_SIGN;

    return central_post_wager(w, sizeof *w);
}


/* =========================================================
 *  2. Prize-claim validation — central-signed response
 * ========================================================= */

struct validation_response {
    char      terminal_id[12];
    uint64_t  request_nonce;
    char      ticket_serial[24];
    uint32_t  prize_cents;            /* 0 = non-winner */
    uint8_t   tier;
    uint32_t  responded_ts;
    uint8_t   sig[384];               /* operator central RSA-3072 */
};

int terminal_validate_prize(const char *ticket_serial,
                            struct validation_response *out)
{
    uint64_t nonce;
    rand_bytes(&nonce, sizeof nonce);

    if (central_request_validation(ticket_serial, nonce, out) != 0)
        return ERR_COMMS;

    /* Bind response to this terminal + nonce so a captured
     * winning response can't be replayed against a losing ticket. */
    if (strncmp(out->terminal_id, local_terminal_id(), 12))
        return ERR_WRONG_TERM;
    if (out->request_nonce != nonce)
        return ERR_NONCE;

    uint8_t h[32];
    sha256_of(out, offsetof(struct validation_response, sig), h);
    if (rsa_pss_verify_sha256(OPERATOR_CENTRAL_PUB,
                              sizeof OPERATOR_CENTRAL_PUB,
                              (uint8_t[]){0x01,0x00,0x01}, 3,
                              h, 32, out->sig, sizeof out->sig) != 0)
        return ERR_SIG;

    if (out->prize_cents > LOCAL_CASH_CAP)
        return ERR_MUST_REDEEM_AT_CLAIM_CENTER;
    return 0;
}


/* =========================================================
 *  3. Draw-result ingest (PowerBall / Mega Millions)
 * ========================================================= */

struct draw_result {
    char      game_code[8];
    uint32_t  draw_number;
    uint32_t  draw_ts;
    uint8_t   mains[6];
    uint8_t   bonus;
    uint64_t  jackpot_cents;
    uint8_t   sig[384];               /* MUSL draw-engine key */
};

int terminal_ingest_draw(const struct draw_result *d)
{
    uint8_t h[32];
    sha256_of(d, offsetof(struct draw_result, sig), h);
    if (rsa_pss_verify_sha256(MUSL_DRAW_PUB, sizeof MUSL_DRAW_PUB,
                              (uint8_t[]){0x01,0x00,0x01}, 3,
                              h, 32, d->sig, sizeof d->sig) != 0)
        return ERR_DRAW_SIG;

    /* Cache for local reprint of winning-number posters; any
     * prize validation still round-trips to central. */
    store_official_draw(d);
    return 0;
}


/* =========================================================
 *  4. Game-DLL load with regulator co-signature
 * ========================================================= */

struct game_pkg {
    char      game_code[8];
    uint32_t  version;
    uint32_t  rules_len;
    uint8_t   rules[65536];           /* payout table, odds, VLT reel */
    uint8_t   operator_sig[384];
    uint8_t   regulator_sig[384];     /* state gaming commission */
};

int terminal_load_game(const struct game_pkg *g)
{
    uint8_t h[32];
    sha256_of(g, offsetof(struct game_pkg, operator_sig), h);
    if (rsa_pss_verify_sha256(OPERATOR_CENTRAL_PUB,
                              sizeof OPERATOR_CENTRAL_PUB,
                              (uint8_t[]){0x01,0x00,0x01}, 3,
                              h, 32, g->operator_sig,
                              sizeof g->operator_sig) != 0)
        return ERR_OP_SIG;
    if (rsa_pss_verify_sha256(REG_GAME_APPROVAL_PUB,
                              sizeof REG_GAME_APPROVAL_PUB,
                              (uint8_t[]){0x01,0x00,0x01}, 3,
                              h, 32, g->regulator_sig,
                              sizeof g->regulator_sig) != 0)
        return ERR_REG_SIG;
    activate_game(g);
    return 0;
}


/* ---- Breakage ---------------------------------------------
 *
 *  Operator central signing root factored:
 *    - Validation responses forgeable — attacker submits losing
 *      ticket, receives forged high-tier response, pays out.
 *    - Terminal game loader accepts rogue game DLLs (must also
 *      forge regulator — but separation is only as strong as
 *      RSA on both sides).
 *
 *  MUSL draw-signing key factored:
 *    - Alternate "official draw result" bulletin accepted by
 *      terminals. Claims pool sabotage; regulatory crisis.
 *
 *  Terminal per-device signing key factored:
 *    - Forged wagers appear to originate from that terminal —
 *      post-draw ticket insertion targeting jackpot payouts.
 */
