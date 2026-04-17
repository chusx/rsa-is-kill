/*
 * lsp_loader_protocol.c
 *
 * ARINC 665 Loadable Software Part (LSP) loader state machine
 * and ARINC 615A "Data Load over Ethernet" transport, as
 * implemented in the aircraft's Data Load Application (DLA)
 * on the Cabin Network Server (CNS) or Portable Data Loader
 * (PDL: Teledyne CMU, CMC ACMS, Honeywell ADL).
 *
 * LSPs update LRU firmware (FMS, FADEC, FCC, FBW, ACARS CMU,
 * IMA partitions on Boeing 787 CCS / Airbus A350 IMA).
 * FAA AC 119-2 / EASA CS-25 Appendix R / DO-326A define the
 * signature requirements; the LSP's Media Set Part Number
 * (MSPN) manifest is RSA-2048/3072 signed by the TC/STC
 * holder's Design Approved Organization (DAO) signing key.
 *
 * The loader is dumb: it enforces the chain, writes the
 * part, and logs to the aircraft's CMC. The attack surface
 * if the TCH/DAO key is factored is "forge arbitrary LRU
 * firmware that any airframe of that type will accept."
 */

#include <stdint.h>
#include <string.h>
#include "arinc665.h"

extern const uint8_t TCH_DAO_ROOT_PUB[384];       /* Boeing / Airbus / GE / P&W */
extern const uint8_t AIRLINE_TECHOPS_PUB[384];    /* airline co-sign            */

enum loader_state {
    S_IDLE, S_FIND_TARGET, S_REQ_INFO,
    S_XFER_MSPM, S_XFER_LUH, S_XFER_BATCH,
    S_VERIFY, S_COMMIT, S_COMPLETE, S_FAIL,
};

/* Media Set Part Number Manifest (665-3 §6). The MSPM is the
 * signed outer envelope; it lists LUH entries which name the
 * actual binary parts. */
struct mspm {
    char       media_set_pn[20];
    char       media_set_check_value[10];
    uint16_t   num_media_set_members;
    /* repeated per-LUH: */
    struct {
        char       luh_pn[24];
        uint32_t   luh_len;
        uint8_t    luh_sha256[32];
        char       target_hw_id[16];  /* "B787-FCC", ...      */
        uint32_t   target_positions;  /* bitmap: L/R/center   */
    } luh[32];
    /* signature over everything above */
    uint8_t    dao_cert[2048]; size_t dao_cert_len;
    uint8_t    airline_cert[2048]; size_t airline_cert_len;
    uint8_t    dao_sig[384];
    uint8_t    airline_sig[384];
};

/* Loadable Unit Header (665-3 §5.4) — per-part wrapper. Each
 * LUH's sha256 is committed to by the MSPM's luh[] table. */
struct luh {
    char       part_pn[24];
    uint32_t   part_type;       /* 1=binary, 2=data, 3=config */
    uint32_t   load_ratio;
    uint8_t    integrity_tag[32];
    /* followed by raw data; not individually signed */
};

int dla_process_mspm(const struct mspm *m, struct loader_ctx *ctx)
{
    if (ctx->state != S_XFER_MSPM) return LOAD_ERR_STATE;

    /* TCH/DAO chain — the type-certificate holder. */
    if (x509_chain_verify(m->dao_cert, m->dao_cert_len,
            TCH_DAO_ROOT_PUB, sizeof TCH_DAO_ROOT_PUB))
        return LOAD_ERR_DAO_CHAIN;

    /* Airline engineering co-signature (DO-326A Part 21 ref). */
    if (x509_chain_verify(m->airline_cert, m->airline_cert_len,
            AIRLINE_TECHOPS_PUB, sizeof AIRLINE_TECHOPS_PUB))
        return LOAD_ERR_AIRLINE_CHAIN;

    uint8_t h[32];
    sha256_of_mspm_tbs(m, h);
    if (verify_with_cert(m->dao_cert, m->dao_cert_len,
                         h, m->dao_sig, sizeof m->dao_sig))
        return LOAD_ERR_DAO_SIG;
    if (verify_with_cert(m->airline_cert, m->airline_cert_len,
                         h, m->airline_sig, sizeof m->airline_sig))
        return LOAD_ERR_AIRLINE_SIG;

    /* Cross-check each LUH's name vs ARINC 615A target HW. */
    for (int i = 0; i < m->num_media_set_members; ++i) {
        if (!target_is_installed(m->luh[i].target_hw_id,
                                 m->luh[i].target_positions))
            return LOAD_ERR_NO_TARGET;
    }

    memcpy(&ctx->mspm, m, sizeof(*m));
    ctx->state = S_XFER_LUH;
    return LOAD_OK;
}

/* After all LUHs have been received, integrity-tag-checked
 * against the MSPM's committed sha256, and staged in the
 * LRU's shadow region, the DLA calls this to flip the
 * partition pointer. This is the final-commit gate. */
int dla_commit_load(struct loader_ctx *ctx)
{
    if (ctx->state != S_VERIFY) return LOAD_ERR_STATE;

    for (int i = 0; i < ctx->mspm.num_media_set_members; ++i) {
        uint8_t h[32];
        sha256_staged_part(ctx->mspm.luh[i].luh_pn, h);
        if (memcmp(h, ctx->mspm.luh[i].luh_sha256, 32))
            return LOAD_ERR_PART_HASH;
    }

    /* Airworthiness Directive compliance check: some LSPs
     * require an AD/SB reference. The CMC logs this for the
     * Continuing Airworthiness Record. */
    cmc_log_load(&ctx->mspm);

    for (int i = 0; i < ctx->mspm.num_media_set_members; ++i)
        lru_partition_swap(ctx->mspm.luh[i].luh_pn);

    ctx->state = S_COMPLETE;
    return LOAD_OK;
}

/* ---- Factored-key effect -----------------------------------
 *   TCH_DAO_ROOT factored (Boeing/Airbus/Embraer/Collins/P&W):
 *     Forge a valid MSPM+LUH pair for any LRU type on that TC
 *     (e.g. a 787 FCC or A350 FCGU). Plug a PDL into the data
 *     load socket on the aircraft (requires ground access to
 *     the airline MRO) and load attacker code into the flight
 *     control computer. Every airframe in that type certifies
 *     the signature.
 *
 *   AIRLINE_TECHOPS_PUB factored:
 *     Bypass the airline co-sign gate — attacker no longer
 *     needs an insider at the MRO to complete the two-signer
 *     requirement.
 *
 *   Recovery: DO-326A Part 21 / Part 43 re-certification of
 *   every LRU type + PDL fleet + airline tooling; measured in
 *   years. Interim posture: FAA/EASA Emergency Airworthiness
 *   Directive restricting software loads, ferry-only
 *   operations, physical loader seal/inspection.
 * ------------------------------------------------------------- */
