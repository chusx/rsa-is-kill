/*
 * elevator_safety_controller.c
 *
 * Otis / Schindler / ThyssenKrupp / KONE elevator controller
 * firmware update and diagnostic unlock. Modern high-rise
 * traction elevators (Otis Gen2, Schindler 7000, KONE MiniSpace)
 * run a SIL-2/SIL-3 safety controller (per EN 81-20/50) that
 * gate-checks all motion commands. Firmware updates to the
 * safety controller are RSA-signed by the OEM; a factored key
 * allows arbitrary firmware = arbitrary motion including
 * overspeed / door-zone violation.
 */

#include <stdint.h>
#include <string.h>
#include "elevator.h"

extern const uint8_t OEM_SAFETY_ROOT_PUB[384];

struct safety_fw_update {
    char       model[16];
    uint32_t   fw_version;
    uint8_t    image_sha256[32];
    uint32_t   min_version;
    uint8_t    oem_cert[2048]; size_t oem_cert_len;
    uint8_t    sig[384];
};

int safety_ctrl_accept_fw(const struct safety_fw_update *u)
{
    if (u->fw_version <= nvram_fw_version()) return ELEV_ROLLBACK;
    if (x509_chain_verify(u->oem_cert, u->oem_cert_len,
            OEM_SAFETY_ROOT_PUB, sizeof OEM_SAFETY_ROOT_PUB))
        return ELEV_CHAIN;
    uint8_t h[32];
    sha256_of(u, offsetof(struct safety_fw_update, oem_cert), h);
    if (verify_with_cert(u->oem_cert, u->oem_cert_len,
                         h, u->sig, sizeof u->sig))
        return ELEV_SIG;
    return flash_stage_fw(u);
}

/* ---- High-rise safety consequence -------------------------
 *  OEM_SAFETY_ROOT factored: replace safety controller FW;
 *  defeat overspeed governor, door-zone interlock, and
 *  leveling checks. EN 81-20 Type A fault = death. Recovery:
 *  every elevator of that OEM model re-commissioned + ASME
 *  A17.1 inspection.
 * --------------------------------------------------------- */
