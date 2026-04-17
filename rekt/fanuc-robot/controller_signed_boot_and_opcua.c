/*
 * controller_signed_boot_and_opcua.c
 *
 * Industrial robot controller bring-up: firmware self-verify at
 * power-on, safety-option package chain-of-trust, OPC UA cert
 * enrollment into the plant-wide GDS, and safety-PLC pairing.
 *
 * Pattern matches FANUC R-30iB Plus, KUKA KR C5, ABB OmniCore,
 * Yaskawa YRC1000. On these controllers it's C/C++ on VxWorks /
 * custom RTOS with a PCIe-attached HSM for key storage.
 */

#include <stdint.h>
#include <string.h>
#include "robot_ctrl.h"
#include "rsa_pkcs1v15.h"
#include "rsa_pss.h"
#include "opcua_pki.h"
#include "profisafe.h"

/* ---- Factory-burned trust anchors ---------------------------- */
extern const uint8_t OEM_FW_SIGN_ROOT_PUB[512];            /* RSA-4096 */
extern const uint8_t OEM_SAFETY_SIGN_ROOT_PUB[512];        /* distinct */
extern const uint8_t OEM_OPCUA_CA_PUB[384];                /* RSA-3072 */
extern const uint8_t PLANT_GDS_TRUST_ANCHOR_PUB[384];      /* customer */


/* ==============================================================
 *  1. Power-on self-verify of main controller firmware
 * ============================================================== */

struct ctrl_fw_manifest {
    char     product[16];
    char     build[32];
    uint32_t rollback_idx;
    uint8_t  kernel_sha256[32];
    uint8_t  motion_planner_sha256[32];
    uint8_t  vision_sha256[32];
    uint8_t  sig[512];              /* RSA-4096 PKCS#1 v1.5 */
};

int controller_fw_self_verify(void)
{
    struct ctrl_fw_manifest *m = flash_read_manifest();

    if (m->rollback_idx < hsm_read_rollback_counter())
        return ERR_ROLLBACK;

    /* Measurement */
    uint8_t h[32];
    sha256_partition(PART_KERNEL,  h);
    if (memcmp(h, m->kernel_sha256, 32))         return ERR_KERNEL;
    sha256_partition(PART_MOTION,  h);
    if (memcmp(h, m->motion_planner_sha256, 32)) return ERR_MOTION;
    sha256_partition(PART_VISION,  h);
    if (memcmp(h, m->vision_sha256, 32))         return ERR_VISION;

    /* RSA verify of manifest signature */
    sha256_of(m, offsetof(struct ctrl_fw_manifest, sig), h);
    return rsa_pkcs1v15_verify_sha256(
        OEM_FW_SIGN_ROOT_PUB, sizeof OEM_FW_SIGN_ROOT_PUB,
        (uint8_t[]){0x01,0x00,0x01}, 3,
        h, 32, m->sig, sizeof m->sig);
}


/* ==============================================================
 *  2. Safety-option package verify (SafeMove / SafeOperation)
 * ==============================================================
 *
 * Safety software is a distinct image: it runs on a physically
 * separate CPU in dual-channel redundant arrangement (TÜV Cat 3 /
 * SIL 2). Its signing key is segregated from the main-CPU key so
 * a compromise of one doesn't automatically compromise the other.
 */

struct safety_option_pkg {
    char      package_id[16];       /* e.g. "ABB-SM-2.3.1" */
    uint8_t   safety_ccf_sha256[32];/* common-cause-failure defeat file */
    uint8_t   sig[512];
};

int safety_option_verify(void)
{
    struct safety_option_pkg *p = read_safety_pkg();
    uint8_t h[32];
    sha256_of(p, offsetof(struct safety_option_pkg, sig), h);
    return rsa_pss_verify_sha256(
        OEM_SAFETY_SIGN_ROOT_PUB, sizeof OEM_SAFETY_SIGN_ROOT_PUB,
        (uint8_t[]){0x01,0x00,0x01}, 3,
        h, 32, p->sig, sizeof p->sig);
}


/* ==============================================================
 *  3. OPC UA enrollment into plant GDS
 * ============================================================== */

int opcua_plant_enroll(void)
{
    /* Generate a CSR (RSA-2048). Private key lives in HSM slot
     * OPCUA_DEVICE_SLOT; CSR contains device-product + serial. */
    uint8_t csr[2048]; size_t csr_len;
    hsm_generate_rsa2048_keypair(OPCUA_DEVICE_SLOT);
    hsm_build_csr(OPCUA_DEVICE_SLOT,
                  "CN=ABB-OmniCore-SN-14221, O=PlantA",
                  csr, &csr_len);

    /* Push CSR to plant Global Discovery Server (GDS) over the
     * GDS Push interface. GDS is the plant-side CA, itself
     * typically backed by an enterprise PKI (Vault, ADCS, EJBCA).
     * Returns a signed cert chained to PLANT_GDS_TRUST_ANCHOR. */
    uint8_t cert[2048]; size_t cert_len;
    uint8_t chain[4096]; size_t chain_len;
    if (gds_push_csr_and_get_cert(csr, csr_len,
                                   cert, &cert_len,
                                   chain, &chain_len) != 0)
        return ERR_GDS_ENROLL;

    if (x509_chain_verify(cert, cert_len,
                           PLANT_GDS_TRUST_ANCHOR_PUB,
                           sizeof PLANT_GDS_TRUST_ANCHOR_PUB) != 0)
        return ERR_BAD_CHAIN;

    hsm_install_cert(OPCUA_DEVICE_SLOT, cert, cert_len);
    return 0;
}


/* ==============================================================
 *  4. Safety-PLC pairing (PROFIsafe over PROFINET)
 * ============================================================== */

int safety_plc_pair_bind(const uint8_t *plc_pair_cert, size_t cert_len,
                          uint8_t plc_rsa_pub[384])
{
    /* A safety PLC (Siemens SIMATIC F-CPU) presents a pairing cert
     * during commissioning. The cert chains to the plant safety-CA,
     * proving this PLC is authorized to exchange F-signals with
     * this robot. */
    if (x509_chain_verify(plc_pair_cert, cert_len,
                           PLANT_GDS_TRUST_ANCHOR_PUB,
                           sizeof PLANT_GDS_TRUST_ANCHOR_PUB) != 0)
        return ERR_SAFETY_CHAIN;

    /* Extract PLC pubkey, save for F-parameter signature checks. */
    size_t n_len, e_len;
    uint8_t e[4];
    if (x509_extract_pub(plc_pair_cert, cert_len,
                          plc_rsa_pub, 384, &n_len,
                          e, 4, &e_len) != 0)
        return ERR_SAFETY_EXTRACT;

    /* F-parameter record (PROFIsafe iParameter), signed by PLC on
     * every safety-function activation, is what the robot now
     * verifies before accepting e-stop release / speed-limit
     * modify commands. */
    store_paired_plc(plc_rsa_pub, n_len);
    return 0;
}


/* ==============================================================
 *  5. Runtime — MES command via OPC UA → motion plan
 * ============================================================== */

int execute_mes_program(const char *prog_name, int cycle_count)
{
    /* 1. OPC UA ReadNode "Current allowed program list" — authorized
     *    programs are signed by the OEM robot-program build tool
     *    (RoboGuide, KUKA WorkVisual, ABB RobotStudio, Motosim).
     *    Production uses a sealed program with an RSA signature
     *    over the compiled KRL / TP / RAPID / INFORM bytecode. */
    struct signed_program *prg = opcua_fetch_program(prog_name);

    uint8_t h[32];
    sha256_of(prg, offsetof(struct signed_program, sig), h);
    if (rsa_pss_verify_sha256(
            OEM_FW_SIGN_ROOT_PUB, sizeof OEM_FW_SIGN_ROOT_PUB,
            (uint8_t[]){0x01,0x00,0x01}, 3,
            h, 32, prg->sig, sizeof prg->sig) != 0)
        return ERR_PROGRAM_SIG;

    /* 2. Check that this program is on the floor-control whitelist
     *    signed by the plant MES, and that the robot is in the
     *    correct safety mode for it (e.g. ABB SafeMove zone). */

    /* 3. Execute motion cycles. F-signal watchdog from paired safety
     *    PLC must be fresh + PLC-RSA-signed within SIL-2 tolerance;
     *    drop of F-signal halts motion. */
    for (int i = 0; i < cycle_count; i++)
        run_program_cycle(prg);

    return 0;
}


/* ==============================================================
 *  Breakage
 * ==============================================================
 *
 *   OEM firmware CA factored:
 *     - Signed controller firmware that subtly drifts motion paths
 *       or disables collaborative-mode safety monitoring on every
 *       unit of that OEM. Injury and production-scrap risk, at
 *       scale across the ~4M-robot global installed base per OEM.
 *
 *   OEM safety-option CA factored:
 *     - Safety-rated software becomes untrusted. TÜV/UL
 *       certification on each deployed cell invalidated; plants
 *       must either fall back to safety-rated fenced mode (loss
 *       of cycle-time) or suspend operation until re-certification.
 *
 *   Plant GDS root factored:
 *     - Attacker mints robot / PLC / MES certs inside the plant
 *       OPC UA namespace, injects MES commands to robots or
 *       mutes safety watchdogs. Plant-floor attack; localized but
 *       kinetic.
 *
 *   Program-signing key factored:
 *     - Upload a malicious RAPID/KRL program that the robot
 *       accepts as "plant-MES-approved"; arbitrary motion with
 *       cryptographic cover.
 */
