/*
 * myjohndeere_telematics_gateway.c
 *
 * John Deere JDLink / Operations Center authenticated command
 * path to the in-cab Gen4 4640 display and the CommandPRO /
 * AutoTrac controller. The cab modem (JDLink 4G/5G) holds a
 * device certificate; Operations Center issues signed
 * "Work Plan" and "Prescription" bundles that the machine
 * consumes.
 *
 * Because the 2015-2023 "right to repair" settlement, the
 * Customer Service Advisor (CSA) tool now also holds a
 * technician RSA cert; there is a third issuer for dealer
 * diagnostic certs. All three roots are RSA-2048, rooted at
 * the John Deere Cybersecurity PKI (internal).
 *
 * Adjacent vendors that share this architectural pattern:
 *   - CNH Industrial (Case IH AFS Connect, New Holland PLM)
 *   - AGCO (Fuse technologies, Fendt Connect)
 *   - Kubota (KubotaNow)
 *   - CLAAS TELEMATICS
 */

#include <stdint.h>
#include <string.h>
#include "jdlink.h"

extern const uint8_t JD_OPCENTER_ROOT_PUB[384];
extern const uint8_t JD_DEALER_ROOT_PUB[384];
extern const uint8_t JD_DEVICE_ROOT_PUB[384];

enum agcmd_kind {
    AGCMD_RX_PRESCRIPTION    = 0x10,   /* variable-rate plan     */
    AGCMD_WORK_PLAN          = 0x11,
    AGCMD_AUTOTRAC_BOUNDARY  = 0x12,   /* geofence               */
    AGCMD_CVE_FW_ACTIVATE    = 0x20,   /* Controller FW Update   */
    AGCMD_RTK_BASE_CONFIG    = 0x30,   /* StarFire / SF-RTK      */
    AGCMD_SERVICEADVISOR     = 0x40,   /* CSA diagnostic unlock  */
    AGCMD_REMOTE_DISABLE     = 0x80,   /* anti-theft / ECU lock  */
};

struct ag_signed_cmd {
    char        serial[16];            /* machine PIN            */
    uint32_t    cmd_seq;
    uint64_t    ts_ns;
    uint8_t     kind;
    uint8_t     payload[4096];
    size_t      payload_len;
    uint8_t     issuer_cert[2048]; size_t issuer_cert_len;
    uint8_t     sig[384];
};

int cab_dispatch_cmd(const struct ag_signed_cmd *c)
{
    if (c->cmd_seq <= nvram_last_seq(c->kind)) return AG_REPLAY;

    const uint8_t *root; size_t root_len;
    switch (c->kind) {
    /* Variable-rate prescription + work plans come from
     * Operations Center; technicians cannot author them. */
    case AGCMD_RX_PRESCRIPTION:
    case AGCMD_WORK_PLAN:
    case AGCMD_AUTOTRAC_BOUNDARY:
        root = JD_OPCENTER_ROOT_PUB;
        root_len = sizeof JD_OPCENTER_ROOT_PUB; break;
    case AGCMD_CVE_FW_ACTIVATE:
    case AGCMD_RTK_BASE_CONFIG:
    case AGCMD_REMOTE_DISABLE:
        root = JD_DEVICE_ROOT_PUB;
        root_len = sizeof JD_DEVICE_ROOT_PUB; break;
    case AGCMD_SERVICEADVISOR:
        root = JD_DEALER_ROOT_PUB;
        root_len = sizeof JD_DEALER_ROOT_PUB; break;
    default: return AG_BAD_KIND;
    }

    if (x509_chain_verify(c->issuer_cert, c->issuer_cert_len,
                          root, root_len))
        return AG_CHAIN;

    uint8_t h[32];
    sha256_of(c, offsetof(struct ag_signed_cmd, issuer_cert), h);
    if (verify_with_cert(c->issuer_cert, c->issuer_cert_len,
                         h, c->sig, sizeof c->sig))
        return AG_SIG;

    nvram_seq_bump(c->kind, c->cmd_seq);

    switch (c->kind) {
    case AGCMD_RX_PRESCRIPTION:   return apply_rx(c->payload, c->payload_len);
    case AGCMD_WORK_PLAN:         return accept_work_plan(c->payload, c->payload_len);
    case AGCMD_AUTOTRAC_BOUNDARY: return autotrac_set_boundary(c->payload);
    case AGCMD_CVE_FW_ACTIVATE:   return cve_fw_swap(c->payload);
    case AGCMD_RTK_BASE_CONFIG:   return sf_rtk_config(c->payload);
    case AGCMD_SERVICEADVISOR:    return csa_unlock(c->payload);
    case AGCMD_REMOTE_DISABLE:    return immobilize_ecu(c->payload);
    }
    return AG_BAD_KIND;
}

/* =========================================================
 *  AGCMD_REMOTE_DISABLE is the feature John Deere used to
 *  brick stolen tractors that left Ukraine in 2022. The
 *  engine ECU latches an IMMOBILIZE flag that only a new
 *  dealer-signed UNLOCK command can clear. A factored dealer
 *  or device root means an attacker can brick every tractor
 *  in a fleet — or unlock stolen ones.
 * ========================================================= */

/* ---- Crop-cycle impact ------------------------------------
 *  - JD_OPCENTER_ROOT factored:
 *      * forge variable-rate Rx: deliberately miss-apply
 *        anhydrous ammonia / seed / fungicide across farms.
 *        Yield damage measured in billions/season.
 *      * forge AutoTrac boundaries: drive combines off
 *        fields / into irrigation equipment at harvest.
 *  - JD_DEVICE_ROOT factored:
 *      * mass remote-disable: North-American row-crop fleet
 *        stalls at planting/harvest. Seasonal timing makes
 *        this a 1-year food-supply attack.
 *      * CVE FW roll: persistent backdoor in tractor
 *        controllers.
 *  Recovery: new PKI + every machine's modem re-provisioned
 *  via CSA cable — measured in dealer-visit years, against a
 *  crop calendar that does not wait.
 * --------------------------------------------------------- */
