/*
 * s7commp_program_download.c
 *
 * S7comm-plus PLC program download / activation state machine.
 * After the TLS-like session in siemens_s7_rsa.c establishes
 * AES-128 confidentiality, TIA Portal uses the S7comm-plus
 * "CreateObject + SetMultiVar" call chain to push compiled
 * OB/FB/FC blocks to the S7-1500 CPU, then calls
 * Plc_Operate(RUN) to activate the new program.
 *
 * The program-download payload is signed by the TIA project
 * certificate (RSA-2048; see tia_verify_project_signature in
 * siemens_s7_rsa.c). The CPU checks this AFTER accepting the
 * blocks into a staging area but BEFORE promoting to active.
 *
 * This file shows the block-upload framing and the promotion
 * gate so the reader understands what exactly runs after a
 * forged signature is accepted.
 */

#include <stdint.h>
#include <string.h>
#include "s7commp.h"

/* S7comm-plus item IDs (subset) */
#define S7CP_OB       0x00010001   /* Organization Block         */
#define S7CP_FB       0x00010002   /* Function Block             */
#define S7CP_FC       0x00010003   /* Function                   */
#define S7CP_DB       0x00010004   /* Data Block                 */
#define S7CP_SDB      0x00010005   /* System Data Block          */

enum dl_state {
    DL_IDLE, DL_SESSION, DL_STAGING, DL_VERIFY, DL_PROMOTE, DL_FAIL,
};

struct block_header {
    uint32_t  item_id;              /* OB/FB/FC/DB/SDB           */
    uint16_t  block_number;
    uint32_t  block_version;
    uint32_t  body_len;
    uint8_t   body_sha256[32];
    /* body follows immediately */
};

struct download_session {
    enum dl_state state;
    uint16_t      n_blocks;
    struct {
        uint32_t  item_id;
        uint16_t  block_number;
        uint32_t  block_version;
        uint8_t   committed_hash[32];
        uint8_t   staged;
    } manifest[256];
    /* project cert + signature from TIA */
    uint8_t       project_cert[2048]; size_t project_cert_len;
    uint8_t       project_sig[256];
};

int s7cp_begin_download(struct download_session *s,
                        const uint8_t *manifest_pdu,
                        size_t pdu_len)
{
    if (s->state != DL_IDLE) return S7CP_ERR_STATE;
    /* Parse manifest (project cert + block list + signature). */
    s7cp_parse_manifest(manifest_pdu, pdu_len, s);
    s->state = DL_STAGING;
    return 0;
}

int s7cp_receive_block(struct download_session *s,
                       const struct block_header *bh,
                       const uint8_t *body)
{
    if (s->state != DL_STAGING) return S7CP_ERR_STATE;

    /* Verify block body hash against committed manifest. */
    uint8_t h[32];
    sha256(body, bh->body_len, h);
    int idx = find_block(s, bh->item_id, bh->block_number);
    if (idx < 0) return S7CP_ERR_NO_SLOT;
    if (memcmp(h, s->manifest[idx].committed_hash, 32))
        return S7CP_ERR_HASH;

    /* Stage into backup flash bank. */
    plc_flash_stage(bh->item_id, bh->block_number, body, bh->body_len);
    s->manifest[idx].staged = 1;
    return 0;
}

int s7cp_end_download(struct download_session *s)
{
    /* All blocks staged? */
    for (int i = 0; i < s->n_blocks; ++i)
        if (!s->manifest[i].staged) return S7CP_ERR_INCOMPLETE;

    s->state = DL_VERIFY;

    /* THE GATE: verify the project certificate signature over
     * the manifest hash (see tia_verify_project_signature in
     * siemens_s7_rsa.c). If the project cert RSA key was
     * factored and the signature forged, this check passes. */
    int r = tia_verify_project_signature(
                (uint8_t *)s->manifest,
                sizeof(s->manifest[0]) * s->n_blocks,
                s->project_sig, sizeof s->project_sig,
                parse_x509(s->project_cert, s->project_cert_len));
    if (r != 1) { s->state = DL_FAIL; return S7CP_ERR_SIG; }

    /* Promote: swap flash banks so the new program is active. */
    s->state = DL_PROMOTE;
    plc_flash_bank_swap();

    /* Issue Plc_Operate(STOP) then Plc_Operate(RUN) to start
     * executing the new program. The CPU's cycle time resumes
     * from OB1 (main scan) with the attacker's ladder logic. */
    plc_stop();
    plc_run();
    s->state = DL_IDLE;
    return 0;
}

/* ---- What happens after promotion -------------------------
 *  The forged program executes at PLC scan-cycle rate (1-50 ms).
 *  Attacker-authored OBs/FBs can:
 *    - Override PID controllers for temperature, pressure,
 *      flow in a chemical plant -> runaway reaction.
 *    - Manipulate VFD setpoints in a rolling mill -> coil
 *      tension loss -> steel slab ejection.
 *    - Disable safety interlock inputs (OB35 / OB80) so
 *      the SIS never sees a demand.
 *    - Report normal process values to the HMI (the Stuxnet
 *      playbook: operator sees green while the process
 *      diverges).
 *  All while the TIA Portal project audit log shows a
 *  cryptographically "valid" project download.
 * --------------------------------------------------------- */
