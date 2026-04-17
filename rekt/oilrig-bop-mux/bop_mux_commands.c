/*
 * bop_mux_commands.c
 *
 * Surface-side MUX control-system interface + subsea pod command
 * parser for a typical deepwater BOP stack (Cameron/NOV/Aker).
 * Enforces: signed firmware at pod boot, two-person signed
 * shear-ram authorisation, signed pressure-test records,
 * signed RTM uplink to operator RTOC.
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include "bop.h"
#include "rsa_pss.h"

extern const uint8_t BOP_OEM_FW_ROOT_PUB[384];      /* Cameron/NOV/etc */
extern const uint8_t RIG_CONTRACTOR_ROOT_PUB[384];  /* OIM credentials */
extern const uint8_t OPERATOR_COMPANY_ROOT_PUB[384];/* operator co-man */


/* =========================================================
 *  1. Subsea pod firmware self-verify at power-up
 * ========================================================= */

struct pod_fw_manifest {
    char      product[20];            /* "CAM 18-3/4 15M", ... */
    char      pod_color[8];           /* "YELLOW" / "BLUE" */
    char      build[32];
    uint32_t  rollback_idx;
    uint8_t   mux_decoder_sha256[32];
    uint8_t   ram_sequencer_sha256[32];
    uint8_t   choke_kill_sha256[32];
    uint8_t   sig[384];
};

int pod_fw_self_verify(void)
{
    struct pod_fw_manifest *m = flash_read_manifest();
    if (m->rollback_idx < secure_rollback()) return ERR_ROLLBACK;

    uint8_t h[32];
    sha256_partition(PART_MUX, h);    if (memcmp(h, m->mux_decoder_sha256, 32)) return ERR_MUX;
    sha256_partition(PART_RAM, h);    if (memcmp(h, m->ram_sequencer_sha256, 32)) return ERR_RAM;
    sha256_partition(PART_CHOKE, h);  if (memcmp(h, m->choke_kill_sha256, 32))  return ERR_CHK;

    sha256_of(m, offsetof(struct pod_fw_manifest, sig), h);
    return rsa_pss_verify_sha256(
        BOP_OEM_FW_ROOT_PUB, sizeof BOP_OEM_FW_ROOT_PUB,
        (uint8_t[]){0x01,0x00,0x01}, 3,
        h, 32, m->sig, sizeof m->sig);
}


/* =========================================================
 *  2. Shear-ram two-person authorisation
 *
 *  Blind-shear / casing-shear rams destroy the drill pipe and
 *  (for casing-shear) render the well unrecoverable. They are
 *  the last-line barrier; actuation must be intentional.
 * ========================================================= */

enum ram_op {
    RAM_PIPE_CLOSE = 1, RAM_PIPE_OPEN = 2,
    RAM_BLIND_SHEAR = 3, RAM_CASING_SHEAR = 4,
    RAM_ANNULAR_CLOSE = 5, RAM_ANNULAR_OPEN = 6,
};

struct ram_command {
    char      rig_id[16];
    char      well_id[24];
    uint32_t  cmd_seq;
    uint32_t  issued_ts;
    uint8_t   op;
    char      oim_id[12];             /* Offshore Installation Manager */
    char      company_man_id[12];     /* operator's representative */
    uint8_t   oim_cert[1024];    size_t oim_cert_len;
    uint8_t   com_cert[1024];    size_t com_cert_len;
    uint8_t   oim_sig[384];
    uint8_t   com_sig[384];
};

int bop_execute_ram(const struct ram_command *c)
{
    if (c->cmd_seq <= last_ram_seq()) return ERR_REPLAY;

    if (x509_chain_verify(c->oim_cert, c->oim_cert_len,
                          RIG_CONTRACTOR_ROOT_PUB,
                          sizeof RIG_CONTRACTOR_ROOT_PUB) ||
        x509_chain_verify(c->com_cert, c->com_cert_len,
                          OPERATOR_COMPANY_ROOT_PUB,
                          sizeof OPERATOR_COMPANY_ROOT_PUB))
        return ERR_CHAIN;

    uint8_t h[32];
    sha256_of(c, offsetof(struct ram_command, oim_sig), h);
    if (verify_with_cert(c->oim_cert, c->oim_cert_len,
                         h, c->oim_sig, sizeof c->oim_sig) ||
        verify_with_cert(c->com_cert, c->com_cert_len,
                         h, c->com_sig, sizeof c->com_sig))
        return ERR_SIG;

    /* Shear-ram envelope: only if toolface is clear of tool-joints
     * per driller's console confirmation.
     */
    if ((c->op == RAM_BLIND_SHEAR || c->op == RAM_CASING_SHEAR)
        && !space_out_ok())
        return ERR_NOT_SPACED_OUT;

    last_ram_seq_bump();
    return mux_send_ram(c->op);
}


/* =========================================================
 *  3. BOP pressure-test result signing (API RP 53)
 * ========================================================= */

struct bop_pressure_test {
    char      rig_id[16];
    char      well_id[24];
    uint32_t  test_ts;
    uint32_t  component_id;           /* BSR, CSR, UA, LA, CK, ... */
    float     test_pressure_psi;
    float     holding_pressure_psi;
    uint32_t  hold_duration_s;        /* API RP 53: 5 min low + 5 min high */
    uint8_t   pass_fail;
    char      witness_id[12];         /* BSEE-approved 3rd party */
    uint8_t   sig[384];
};

int bop_sign_pressure_test(struct bop_pressure_test *pt)
{
    pt->test_ts = (uint32_t)time(NULL);
    uint8_t h[32];
    sha256_of(pt, offsetof(struct bop_pressure_test, sig), h);
    return rsa_pss_sign_sha256_hsm(
        RIG_TEST_KEY, h, 32, pt->sig, sizeof pt->sig);
}


/* =========================================================
 *  4. RTM uplink to operator RTOC
 * ========================================================= */

struct rtm_batch {
    char      rig_id[16];
    char      well_id[24];
    uint32_t  period_start, period_end;
    uint32_t  n_samples;
    float     spp_psi[720];           /* stand-pipe pressure */
    float     pit_bbl[720];           /* active-pit volume */
    float     rop_fph[720];           /* rate of penetration */
    float     flow_out_gpm[720];      /* early kick detection */
    uint8_t   sig[384];
};

int bop_emit_rtm(struct rtm_batch *b)
{
    uint8_t h[32];
    sha256_of(b, offsetof(struct rtm_batch, sig), h);
    return rsa_pss_sign_sha256_hsm(
        RIG_RTM_KEY, h, 32, b->sig, sizeof b->sig);
}


/* ---- Breakage ---------------------------------------------
 *
 *  BOP OEM FW root factored:
 *    - Malicious subsea-pod firmware across installed base;
 *      last-line well-control barrier silently disabled.
 *      Macondo-class blowout risk without insider path.
 *
 *  Rig contractor OIM root factored:
 *    - Spurious shear-ram actuation destroys pipe + well. Tens
 *      of millions of dollars per event; plausible-deniability
 *      attack by competitor or state actor.
 *
 *  Operator company-man root factored:
 *    - Forged company-man co-signature bypasses two-person
 *      control on last-line barrier.
 *
 *  RTM signing factored:
 *    - Incident-investigation chain broken; BSEE forced to
 *      impose drilling restrictions fleet-wide.
 */
