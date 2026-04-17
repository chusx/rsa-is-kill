/*
 * slte_ems_and_wetplant.c
 *
 * Submarine cable landing-station SLTE (Submarine Line Terminal
 * Equipment) side: firmware self-verify, EMS-to-SLTE authenticated
 * command ingest, and signed line-monitoring (COTDR) trace
 * emission. Pattern aligns with SubCom TSM / ASN EMS / NEC SpaNet.
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include "slte.h"
#include "rsa_pkcs1v15.h"
#include "rsa_pss.h"

extern const uint8_t VENDOR_FW_ROOT_PUB[512];        /* SubCom/ASN/NEC */
extern const uint8_t CONSORTIUM_OPS_ROOT_PUB[384];   /* per-cable ops PKI */


/* =========================================================
 *  1. SLTE firmware self-verify at boot
 * ========================================================= */

struct slte_fw_manifest {
    char      product[16];            /* "SubCom C100", "ASN 1620LM" */
    char      build[32];
    uint32_t  rollback_idx;
    uint8_t   linecard_sha256[32];
    uint8_t   fec_sha256[32];
    uint8_t   dsp_sha256[32];
    uint8_t   ems_agent_sha256[32];
    uint8_t   sig[512];
};

int slte_fw_self_verify(void)
{
    struct slte_fw_manifest *m = flash_read_manifest();
    if (m->rollback_idx < hsm_rollback()) return ERR_ROLLBACK;

    uint8_t h[32];
    sha256_partition(PART_LINECARD, h);
    if (memcmp(h, m->linecard_sha256, 32)) return ERR_LC;

    sha256_of(m, offsetof(struct slte_fw_manifest, sig), h);
    return rsa_pkcs1v15_verify_sha256(
        VENDOR_FW_ROOT_PUB, sizeof VENDOR_FW_ROOT_PUB,
        (uint8_t[]){0x01,0x00,0x01}, 3,
        h, 32, m->sig, sizeof m->sig);
}


/* =========================================================
 *  2. Consortium-signed command execution
 *
 *  Commands that touch capacity provisioning, pump-laser power,
 *  branching-unit state, or OSNR-impacting settings must carry
 *  a signature from the consortium operations PKI. Routine
 *  read-only telemetry does not.
 * ========================================================= */

struct consortium_cmd {
    char      cable_id[16];           /* "MAREA", "DUNANT", "2AFRICA" */
    uint32_t  cmd_seq;                /* monotonic */
    uint32_t  issued_ts;
    uint16_t  cmd_type;               /* 1=PUMP 2=BU-SW 3=CAP-MOVE ... */
    uint16_t  target_node;            /* repeater / BU / SLTE id */
    uint32_t  arg0, arg1;
    uint8_t   signer_cert[2048];
    size_t    cert_len;
    uint8_t   sig[384];
};

static uint32_t last_cmd_seq;

int slte_execute_consortium_cmd(const struct consortium_cmd *c)
{
    if (c->cmd_seq <= last_cmd_seq) return ERR_REPLAY;

    if (strncmp(c->cable_id, local_cable_id(), 16))
        return ERR_WRONG_CABLE;

    if (x509_chain_verify(c->signer_cert, c->cert_len,
                          CONSORTIUM_OPS_ROOT_PUB,
                          sizeof CONSORTIUM_OPS_ROOT_PUB) != 0)
        return ERR_CHAIN;

    uint8_t n[384], e[4];
    size_t n_len, e_len;
    x509_extract_pub(c->signer_cert, c->cert_len,
                     n, sizeof n, &n_len, e, sizeof e, &e_len);

    uint8_t h[32];
    sha256_of(c, offsetof(struct consortium_cmd, sig), h);
    if (rsa_pss_verify_sha256(n, n_len, e, e_len,
                              h, 32, c->sig, sizeof c->sig) != 0)
        return ERR_CMD_SIG;

    last_cmd_seq = c->cmd_seq;

    switch (c->cmd_type) {
    case 1: /* PUMP */
        /* Pump-laser power changes affect OSNR across the whole
         * span. Rate-limit + envelope-bound here as defence in
         * depth. */
        if (c->arg0 > MAX_PUMP_MW) return ERR_ENVELOPE;
        set_pump_power(c->target_node, c->arg0);
        break;
    case 2: /* Branching unit switch — re-routes traffic between
             * landing stations. A high-sensitivity command. */
        request_bu_switch(c->target_node, c->arg0);
        break;
    case 3: /* Capacity move — wavelength relight */
        provision_wavelength(c->target_node, c->arg0, c->arg1);
        break;
    }
    return 0;
}


/* =========================================================
 *  3. Line-monitoring signed COTDR trace emission
 *
 *  SLTE periodically emits a COTDR trace of the span out to
 *  ~10,000 km. The trace is signed before being written to the
 *  vendor LMS database so fault localisation used in insurance /
 *  attribution is evidentiarily sound.
 * ========================================================= */

struct cotdr_trace {
    char      slte_serial[16];
    uint32_t  ts;
    uint32_t  n_samples;
    int16_t   power_dB_x100[32768];   /* OTDR reflectance curve */
    uint8_t   slte_cert[1536];
    size_t    cert_len;
    uint8_t   sig[384];
};

int slte_emit_signed_cotdr(struct cotdr_trace *t)
{
    t->ts = (uint32_t)time(NULL);
    t->n_samples = cotdr_capture(t->power_dB_x100, 32768);
    slte_export_cert(t->slte_cert, sizeof t->slte_cert, &t->cert_len);

    uint8_t h[32];
    sha256_of(t, offsetof(struct cotdr_trace, sig), h);
    return rsa_pss_sign_sha256_hsm(
        SLTE_SIGNING_KEY, h, 32, t->sig, sizeof t->sig);
}


/* ---- Breakage ---------------------------------------------
 *
 *  Vendor SLTE fw root factored:
 *    - Signed firmware that mis-tunes pump lasers or FEC margin
 *      across multiple cables of that vendor. Simultaneous
 *      inter-continental throughput collapse.
 *
 *  Consortium ops root factored:
 *    - Unauthorised branching-unit switches silently re-route
 *      traffic toward attacker-operated landings. SIGINT at
 *      trans-ocean scale; attribution exists only in the
 *      EMS-side logs the attacker can also forge.
 *
 *  SLTE per-unit signing key factored:
 *    - COTDR trace forgeries mis-locate cable faults. Repair
 *      vessels dispatched to wrong coordinates (~$500k/day
 *      ship cost). Attribution of deliberate cable cuts becomes
 *      contestable.
 */
