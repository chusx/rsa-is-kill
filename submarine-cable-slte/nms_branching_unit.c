/*
 * nms_branching_unit.c
 *
 * Submarine Line Terminal Equipment (SLTE) Network Management
 * System signed-command path for a Branching Unit (BU). BUs
 * are the T-shaped wet-plant devices that split a trunk fibre
 * pair into two landing stations; their power feed and OADM
 * configuration are reprogrammable in situ over the cable's
 * management wavelength (typically a 1510 nm supervisory ch.)
 * from the landing station NMS.
 *
 * Vendors:
 *   - SubCom (TE SubCom / CIENA-acquired 2024) — SURIKATA NMS
 *   - Alcatel Submarine Networks (ASN) — AEM / WaveSurfer
 *   - NEC Submarine — NEC U-node
 *   - HMN (Huawei Marine) — iManager U2000-SuperiorNet
 *
 * Signed over RSA-2048 today; some ASN deployments have moved
 * to RSA-3072 per GlobalConnect tender spec. The landing-station
 * NMS holds the operator root; wet-plant branching units
 * and repeaters ship with the OEM root fused at the factory.
 * Rotation requires a ship recovery of the BU — weeks on
 * station at ~$150k/day charter for a CS (cable ship).
 */

#include <stdint.h>
#include <string.h>
#include "slte.h"

extern const uint8_t OEM_WETPLANT_ROOT[384];      /* per vendor  */
extern const uint8_t OPERATOR_NMS_ROOT[384];      /* consortium  */

enum bu_command {
    BU_POWER_REDIRECT    = 0x10,    /* shift 10 kV feed N->S    */
    BU_OADM_RECONFIG     = 0x20,    /* lambda add/drop          */
    BU_LOOPBACK          = 0x30,    /* fault-isolation loopback */
    BU_SHUTDOWN_BRANCH   = 0x40,    /* isolate a landing        */
    BU_FIRMWARE_ACTIVATE = 0x80,    /* swap to staged FW        */
};

struct bu_signed_command {
    char       cable_system_id[16];    /* "MAREA","2AFRICA"      */
    char       bu_id[12];              /* "BU03"                 */
    uint32_t   cmd_seq;
    uint64_t   issued_utc_ns;
    uint8_t    command;
    uint8_t    params[64];             /* command-specific      */
    /* two-signer: consortium NOC + vendor TAC, per IOCP        */
    uint8_t    noc_cert[2048]; size_t noc_cert_len;
    uint8_t    tac_cert[2048]; size_t tac_cert_len;
    uint8_t    noc_sig[384];
    uint8_t    tac_sig[384];
};

int bu_accept_command(const struct bu_signed_command *c)
{
    if (c->cmd_seq <= bu_last_seq(c->bu_id)) return BU_REPLAY;

    /* NOC (operator/consortium) chain */
    if (x509_chain_verify(c->noc_cert, c->noc_cert_len,
            OPERATOR_NMS_ROOT, sizeof OPERATOR_NMS_ROOT))
        return BU_NOC_CHAIN;

    /* TAC (vendor Technical Assistance Center) chain */
    if (x509_chain_verify(c->tac_cert, c->tac_cert_len,
            OEM_WETPLANT_ROOT, sizeof OEM_WETPLANT_ROOT))
        return BU_TAC_CHAIN;

    uint8_t h[32];
    sha256_of(c, offsetof(struct bu_signed_command, noc_cert), h);

    if (verify_with_cert(c->noc_cert, c->noc_cert_len,
                         h, c->noc_sig, sizeof c->noc_sig))
        return BU_NOC_SIG;
    if (verify_with_cert(c->tac_cert, c->tac_cert_len,
                         h, c->tac_sig, sizeof c->tac_sig))
        return BU_TAC_SIG;

    /* Latency tolerance on supervisory channel is generous
     * (20 s) because the 1510 nm link round-trips through
     * thousands of km of fibre and repeaters. */
    if (abs_ns_delta(c->issued_utc_ns) > 20ULL * 1000000000ULL)
        return BU_STALE;

    bu_last_seq_bump(c->bu_id, c->cmd_seq);

    switch (c->command) {
    case BU_POWER_REDIRECT:    return bu_pfe_redirect(c->params);
    case BU_OADM_RECONFIG:     return bu_oadm_program(c->params);
    case BU_LOOPBACK:          return bu_loopback(c->params);
    case BU_SHUTDOWN_BRANCH:   return bu_isolate(c->params);
    case BU_FIRMWARE_ACTIVATE: return bu_fw_swap(c->params);
    }
    return BU_BAD_CMD;
}

/* =========================================================
 *  Power Feed Equipment (PFE) at the landing station feeds
 *  the cable with ±10 kV DC; the BU is the midpoint that
 *  chooses which side of the cable carries current. Mis-
 *  programming a BU_POWER_REDIRECT can shunt fault current
 *  through repeaters, damaging dozens of Erbium-doped fibre
 *  amplifiers simultaneously.
 * ========================================================= */

/* ---- Consequence when OEM_WETPLANT_ROOT factored ----------
 *  - BU_OADM_RECONFIG: silent lambda-level MitM on specific
 *    wavelengths. 2AFRICA / SEA-ME-WE 6 type systems carry
 *    aggregated international trunk; a hijacked lambda =
 *    sovereign-scale traffic intercept.
 *  - BU_SHUTDOWN_BRANCH: strand a landing country from the
 *    internet. Tonga 2022-class event but cryptographically
 *    induced rather than geological.
 *  - BU_FIRMWARE_ACTIVATE: replace BU firmware; persistent
 *    wet-plant access until cable ship retrieval.
 *  Recovery: wet-plant refresh is measured in cable-system
 *  upgrade cycles (15-25 years). Emergency mitigation is
 *  landing-station-side spectrum monitoring + out-of-band
 *  attestation, neither of which close the signature gap.
 * --------------------------------------------------------- */
