/*
 * cbtc_movement_authority.c
 *
 * Communication-Based Train Control (CBTC) — IEEE 1474.1
 * movement authority (MA) from zone controller to on-board
 * ATP. CBTC runs every modern metro: NYC 7/L/Canarsie,
 * Paris Lines 1/14, Singapore NEL/DTL/TEL, London Elizabeth
 * Line, Delhi Metro (Alstom Urbalis / Siemens Trainguard MT /
 * Thales SelTrac / Hitachi Rail).
 *
 * The ATC wayside zone controller issues MAs over a radio
 * (WiFi 5 GHz or LTE-R) channel authenticated with RSA-signed
 * session keys (per IEC 62280 / EN 50129 SIL-4 comms).
 */

#include <stdint.h>
#include <string.h>
#include "cbtc.h"

extern const uint8_t ATC_ZONE_ROOT_PUB[384];

struct cbtc_ma {
    uint32_t  train_id;
    uint32_t  zone_id;
    uint32_t  ma_seq;
    float     eoa_m;                    /* end of authority, m     */
    float     max_speed_mps;
    float     gradient_permil;
    uint8_t   platform_screen_doors;   /* 1 = PSD-enabled station */
    uint8_t   mac[16];                 /* HMAC-SHA256 trunc'd     */
};

/* Session key was RSA-transported at zone-controller <-> OBU
 * handoff (similar to ERTMS SUBSET-037). */
int obu_accept_ma(const struct cbtc_session *s,
                  const struct cbtc_ma *ma)
{
    if (ma->zone_id != s->zone_id) return CBTC_WRONG_ZONE;
    if (ma->ma_seq <= s->last_ma_seq) return CBTC_REPLAY;

    uint8_t computed[16];
    hmac_sha256_truncated(s->session_key, 32,
                          ma, offsetof(struct cbtc_ma, mac),
                          computed);
    if (memcmp(computed, ma->mac, 16)) return CBTC_MAC;

    /* Safety: if EoA < current position, emergency brake. */
    if (ma->eoa_m < obu_position_m()) {
        emergency_brake();
        return CBTC_EB;
    }

    s->last_ma_seq = ma->ma_seq;
    atp_install_ma(ma->eoa_m, ma->max_speed_mps);
    return CBTC_OK;
}

/* ---- Collision / derailment surface -----------------------
 *  ATC_ZONE_ROOT factored:
 *    Forge session establishment -> attacker-chosen session key
 *    -> forge arbitrary MAs. Two trains on the same track
 *    section with overlapping MAs -> rear-end or head-on
 *    collision (CBTC headway as low as 90 s). Or issue MA
 *    with max_speed exceeding curve limit -> derailment in
 *    tunnel. Detection: ATC sees duplicate/conflicting sessions
 *    only if monitoring is enabled per zone. Recovery: transit
 *    authority rotates CBTC PKI per zone controller; SIL-4
 *    re-commissioning per EN 50129.
 * --------------------------------------------------------- */
