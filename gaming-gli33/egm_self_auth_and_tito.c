/*
 * egm_self_auth_and_tito.c
 *
 * Electronic Gaming Machine self-authentication + TITO ticket
 * signing on an IGT Advantage / Bally Alpha 2 / Konami SYNK-class
 * platform. Runs at every boot (self-auth), on regulator audit
 * request (on-demand rehash + RSA verify), and at each ticket
 * print + redemption event.
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include "egm_platform.h"
#include "rsa_pkcs1v15.h"
#include "rsa_pss.h"
#include "sha256.h"

/* ---- Anchors stored in tamper-evident secure element ---------- */

extern const uint8_t GLI_CERT_ROOT_PUB[512];     /* RSA-4096 */
extern const uint8_t OEM_FW_SIGN_PUB[512];       /* OEM code-sign */
extern const uint8_t OP_TITO_SIGN_PRIV_HANDLE;   /* operator key */
extern const uint8_t STATE_GCB_ROOT_PUB[384];    /* state regulator */


/* ==================================================================
 * 1. Power-on self-authentication (GLI-11 §3.4)
 * ================================================================== */

struct firmware_manifest {
    char      game_title_id[32];
    char      paytable_id[16];       /* e.g. "BUFFALO-GOLD-92-00" */
    uint32_t  rtp_bps;               /* return-to-player basis points */
    uint8_t   code_sha256[32];
    uint8_t   rng_module_sha256[32];
    uint8_t   graphics_sha256[32];
    uint8_t   sound_sha256[32];
    uint8_t   oem_sig[512];          /* OEM RSA-4096 signature */
    uint8_t   gli_sig[512];          /* GLI lab signature */
};

int egm_power_on_self_auth(void)
{
    struct firmware_manifest *m = read_manifest_from_flash();

    /* Rehash each game-code partition and compare. */
    uint8_t measured[32];
    sha256_partition(PART_GAME_CODE, measured);
    if (memcmp(measured, m->code_sha256, 32)) return SELF_AUTH_FAIL;
    sha256_partition(PART_RNG, measured);
    if (memcmp(measured, m->rng_module_sha256, 32)) return SELF_AUTH_FAIL;

    /* Verify dual signatures. OEM sig proves the OEM built it;
     * GLI sig proves the lab certified it. Both must pass. */
    uint8_t hash_over_manifest[32];
    sha256_of(m, offsetof(struct firmware_manifest, oem_sig),
              hash_over_manifest);

    if (rsa_pkcs1v15_verify_sha256(OEM_FW_SIGN_PUB, 512,
                                    (uint8_t[]){0x01,0x00,0x01}, 3,
                                    hash_over_manifest, 32,
                                    m->oem_sig, 512) != 0)
        return SELF_AUTH_FAIL;

    if (rsa_pss_verify_sha256(GLI_CERT_ROOT_PUB, 512,
                               (uint8_t[]){0x01,0x00,0x01}, 3,
                               hash_over_manifest, 32,
                               m->gli_sig, 512) != 0)
        return SELF_AUTH_FAIL;

    /* Log to the tilt-protected event log for regulator retrieval. */
    event_log_append(EVT_POWER_ON_SELF_AUTH_PASS, time(NULL),
                     m->game_title_id, m->paytable_id);
    return SELF_AUTH_OK;
}


/* ==================================================================
 * 2. On-demand regulator audit (Nevada GCB tech, NJ DGE, MGCB)
 * ================================================================== */

int egm_emit_self_auth_report(uint8_t *out, size_t *len)
{
    /* Called when a state gaming commission auditor connects a
     * portable audit device (SANS appliance, GCB Techauditor) and
     * asks the machine to prove its running firmware matches a
     * lab-certified manifest. */
    struct firmware_manifest *m = read_manifest_from_flash();

    /* Compile live measurements + manifest signature blob + a
     * machine-specific RSA countersignature over "this is what I'm
     * running right now, at time T, with serial S". */
    struct self_auth_report rep;
    strcpy(rep.machine_serial, EGM_SERIAL_NUMBER);
    rep.ts = time(NULL);
    memcpy(&rep.manifest, m, sizeof *m);
    sha256_partition(PART_GAME_CODE, rep.live_code_hash);
    sha256_partition(PART_RNG,       rep.live_rng_hash);

    uint8_t h[32];
    sha256_of(&rep, sizeof rep, h);
    rsa_pss_sign_sha256_hsm(OP_TITO_SIGN_PRIV_HANDLE,
                             h, 32, rep.machine_sig, 256);

    memcpy(out, &rep, sizeof rep);
    *len = sizeof rep;
    return 0;
}


/* ==================================================================
 * 3. TITO ticket print + signed redemption
 * ================================================================== */

struct tito_ticket {
    char     ticket_id[18];       /* 18-digit barcode */
    uint64_t amount_cents;
    uint64_t print_ts;
    char     machine_serial[16];
    char     casino_license[16];
    uint8_t  sig[256];            /* RSA-2048 operator sig */
};

int egm_print_tito(uint64_t amount_cents, struct tito_ticket *t)
{
    rand_ticket_id(t->ticket_id);
    t->amount_cents = amount_cents;
    t->print_ts = time(NULL);
    strcpy(t->machine_serial, EGM_SERIAL_NUMBER);
    strcpy(t->casino_license, CASINO_LICENSE_ID);

    uint8_t h[32];
    sha256_of(t, offsetof(struct tito_ticket, sig), h);
    rsa_pkcs1v15_sign_sha256_hsm(OP_TITO_SIGN_PRIV_HANDLE,
                                  h, 32, t->sig, 256);

    thermal_print_barcode_and_data(t);

    /* Parallel path: send signed "ticket issued" event to central
     * TITO server (IGT EZPay, Konami Synkros, Everi CashClub) over
     * TLS-mutual-auth; cashless kiosk redemption queries the server
     * with the barcode and checks the signature + "not yet
     * redeemed" flag before paying out. */
    tito_server_post_event(TITO_EVT_ISSUE, t);
    return 0;
}


/* ==================================================================
 * 4. Cashless kiosk redemption
 * ================================================================== */

int kiosk_redeem_tito(const char *ticket_id,
                       const uint8_t *presented_sig, size_t sig_len,
                       struct tito_ticket *server_record)
{
    /* Fetch server-stored ticket record; verify both:
     *   (a) RSA signature binds ticket_id + amount + machine_serial
     *   (b) not marked redeemed previously.  */
    if (strcmp(server_record->ticket_id, ticket_id) != 0) return -1;

    uint8_t h[32];
    sha256_of(server_record,
              offsetof(struct tito_ticket, sig), h);
    if (rsa_pkcs1v15_verify_sha256(
            OP_TITO_SIGN_PUB, 256,
            (uint8_t[]){0x01,0x00,0x01}, 3,
            h, 32,
            server_record->sig, 256) != 0) return -1;

    if (server_record_is_redeemed(ticket_id)) return -1;
    mark_redeemed(ticket_id);

    cash_out(server_record->amount_cents);
    return 0;
}


/* ---- Breakage --------------------------------------------------
 *
 *   Factor the OEM firmware-signing key:
 *     Ship a "legit" firmware update that passes power-on self-
 *     auth, regulator audit, AND lab-signature verification if the
 *     attacker also forged the GLI sig (see next). Altered paytable
 *     RTP drops the house-favorable return by several basis points;
 *     over a casino's fleet of thousands of machines this extracts
 *     millions/month undetected.
 *
 *   Factor the GLI certification key:
 *     Forge manifest signatures declaring arbitrary firmware
 *     "lab-certified". Regulator audit tools trust it. Combined
 *     with OEM-key break = full paytable manipulation fleet-wide.
 *
 *   Factor the operator TITO signing key:
 *     Counterfeit TITO tickets redeemable at cashless kiosks.
 *     Traditional defense is the "not-yet-redeemed" flag on the
 *     central server, but attackers with valid-looking signed
 *     tickets can bypass reconciliation by exploiting timing
 *     windows during nightly reconciliation batch flushes.
 *
 *   Factor the state gaming commission root:
 *     Mint machine registration certs binding attacker-controlled
 *     serials to a licensed casino floor. Regulatory audit evidence
 *     chain collapses.
 */
