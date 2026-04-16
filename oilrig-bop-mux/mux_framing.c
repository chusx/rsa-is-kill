/*
 * mux_framing.c
 *
 * Surface-to-subsea MUX cable framing for deepwater BOP
 * (Cameron MUX, NOV AMPHION, Aker Solutions DrillPilot). Two
 * redundant pods (YELLOW/BLUE) each carry a 20 kbit/s FSK channel
 * down the umbilical; commands are double-encoded and arbitrated
 * by a pod-resident voter. Per API RP 53 / API 17D this is the
 * primary safety-critical control path to the stack.
 *
 * References:
 *   - API RP 53 (Blowout Prevention Equipment Systems)
 *   - API Spec 17D (Subsea Wellhead/Christmas Tree)
 *   - BSEE 30 CFR 250.734 (WCD / SEMS II crypto assurance)
 *
 * This file is the transport layer UNDER bop_mux_commands.c; the
 * ram_command / pod_fw_manifest structs there ride inside these
 * frames, and the signed payload is opaque to the MUX voter.
 */

#include <stdint.h>
#include <string.h>
#include "bop.h"

#define MUX_SYNC0      0x7E
#define MUX_SYNC1      0x81
#define MUX_MAX_PAY    1400            /* fits a ram_command + two certs */

enum mux_chan { MUX_YELLOW = 0, MUX_BLUE = 1 };

enum mux_pdu_type {
    PDU_HEARTBEAT        = 0x01,
    PDU_TELEMETRY        = 0x10,       /* pod -> surface, unsigned */
    PDU_COMMAND_SIGNED   = 0x20,       /* surface -> pod, RSA-PSS */
    PDU_FW_CHUNK         = 0x30,       /* firmware roll, chunked   */
    PDU_PRESSURE_REPORT  = 0x40,       /* pod -> surface, signed   */
    PDU_ACK              = 0x7F,
    PDU_NAK              = 0x7E,
};

struct mux_frame_hdr {
    uint8_t   sync[2];                 /* 0x7E 0x81 */
    uint8_t   chan;                    /* YELLOW=0, BLUE=1        */
    uint8_t   pdu_type;
    uint16_t  pdu_len;                 /* big-endian on wire      */
    uint32_t  frame_seq;               /* monotonic per channel   */
    uint8_t   rig_id[4];
    uint16_t  hdr_crc16;               /* CRC-16/CCITT over hdr-8 */
};

/* Payload CRC is CRC-32/MPEG-2 trailing the PDU. Replay / forgery
 * protection is NOT in the CRC — that is the RSA-PSS sig inside
 * the PDU (see bop_mux_commands.c). CRC is line-noise only. */

int mux_validate_frame(const uint8_t *buf, size_t len,
                       struct mux_frame_hdr *out)
{
    if (len < sizeof(*out) + 4) return ERR_SHORT;
    memcpy(out, buf, sizeof(*out));
    if (out->sync[0] != MUX_SYNC0 || out->sync[1] != MUX_SYNC1)
        return ERR_SYNC;
    if (crc16_ccitt(buf, 8) != be16toh(out->hdr_crc16))
        return ERR_HDR_CRC;
    if (be16toh(out->pdu_len) > MUX_MAX_PAY) return ERR_TOO_BIG;
    if (crc32_mpeg2(buf + sizeof(*out), be16toh(out->pdu_len)) !=
        read_be32(buf + sizeof(*out) + be16toh(out->pdu_len)))
        return ERR_PAY_CRC;
    return 0;
}

/* YELLOW / BLUE voter. Both pods run identical sequencer firmware
 * and must agree on cmd_seq + hash(payload) before the sequencer
 * drives the SPM valve coil. Disagreement = latching fault; the
 * toolpusher must reset the pod from the driller's chair. */
int mux_pod_voter(const struct mux_frame_hdr *y,
                  const uint8_t *y_pay,
                  const struct mux_frame_hdr *b,
                  const uint8_t *b_pay)
{
    if (y->pdu_type != b->pdu_type) return POD_DISAGREE;
    if (be16toh(y->pdu_len) != be16toh(b->pdu_len)) return POD_DISAGREE;
    if (memcmp(y_pay, b_pay, be16toh(y->pdu_len))) return POD_DISAGREE;
    /* seq may legitimately differ by ±1 across channels during
     * umbilical retransmit windows; voter tolerates up to ±3. */
    int32_t d = (int32_t)(be32toh(y->frame_seq) - be32toh(b->frame_seq));
    if (d > 3 || d < -3) return POD_DISAGREE;
    return POD_AGREE;
}

/* =========================================================
 *  Firmware roll transport: 4 KiB chunks, last chunk carries
 *  the pod_fw_manifest (see bop_mux_commands.c). A pod will
 *  stage chunks in scratch flash, verify RSA-PSS on the
 *  manifest, then atomic-swap into the active slot.
 * ========================================================= */
struct fw_chunk_pdu {
    uint32_t  build_id;
    uint16_t  chunk_idx;
    uint16_t  chunk_total;
    uint8_t   sha256[32];              /* per-chunk integrity */
    uint8_t   data[];                  /* up to MUX_MAX_PAY-40 */
};

int mux_fw_stage_chunk(const struct fw_chunk_pdu *c, size_t clen)
{
    uint8_t h[32];
    sha256(c->data, clen - sizeof(*c), h);
    if (memcmp(h, c->sha256, 32)) return ERR_CHUNK_HASH;
    return flash_stage_write(c->build_id, c->chunk_idx, c->data,
                             clen - sizeof(*c));
}

/* ---- Attack surface once BOP_OEM_FW_ROOT_PUB is factored ----
 *
 *  The MUX voter has no authentication — its only discriminator
 *  between legit surface console and attacker is whether the
 *  enclosed RSA-PSS signature verifies against
 *  BOP_OEM_FW_ROOT_PUB (firmware) / RIG_CONTRACTOR_ROOT_PUB (ops).
 *  Forged sig -> both pods vote AGREE -> sequencer drives the
 *  SPM coil -> blind-shear actuates with no space-out check
 *  abort path, because the signed payload *said* space-out was
 *  confirmed. Kinetic consequence at the BSR tool joint.
 */
