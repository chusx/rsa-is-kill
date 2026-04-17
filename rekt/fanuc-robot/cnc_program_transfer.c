/*
 * cnc_program_transfer.c
 *
 * FANUC / KUKA / ABB industrial robot and CNC controller
 * program transfer with RSA-signed program verification.
 * FANUC Roboguide / KUKA WorkVisual / ABB RobotStudio push
 * compiled programs to the controller over EtherNet/IP or
 * ProfiNet; newer controllers (FANUC R-30iB+, KUKA KR C5,
 * ABB OmniCore) verify an RSA signature before accepting.
 *
 * This protects against unauthorized program changes that
 * could alter robot motion paths in an automotive body shop,
 * semiconductor fab, or pharma clean-room.
 */

#include <stdint.h>
#include <string.h>
#include "fanuc.h"

extern const uint8_t OEM_PROGRAM_ROOT_PUB[384];

struct robot_program {
    char       cell_id[16];
    char       program_name[32];       /* "SPOTW_LH_DOOR_03"    */
    uint32_t   revision;
    uint32_t   motion_group_mask;      /* which axes/tools       */
    uint8_t    program_sha256[32];     /* over binary TP/Karel   */
    uint32_t   program_len;
    uint8_t    eng_cert[2048]; size_t eng_cert_len;
    uint8_t    sig[384];
};

int controller_accept_program(const struct robot_program *p)
{
    if (p->revision <= nvram_program_rev(p->program_name))
        return ROB_ROLLBACK;
    if (x509_chain_verify(p->eng_cert, p->eng_cert_len,
            OEM_PROGRAM_ROOT_PUB, sizeof OEM_PROGRAM_ROOT_PUB))
        return ROB_CHAIN;
    uint8_t h[32];
    sha256_of(p, offsetof(struct robot_program, eng_cert), h);
    if (verify_with_cert(p->eng_cert, p->eng_cert_len,
                         h, p->sig, sizeof p->sig))
        return ROB_SIG;

    /* Load program into teach-pendant RAM; activate on next
     * cycle start. If the program is for a 6-axis spot-welder
     * in a body shop, a malicious path can:
     *   - Miss weld spots -> structural weakness at 100k cars
     *   - Collide with fixtures/operators in manual mode
     *   - Exceed joint-torque limits -> mechanical damage      */
    return program_stage(p->program_name, p->program_len);
}

/* ---- Manufacturing sabotage surface -----------------------
 *  OEM_PROGRAM_ROOT factored:
 *    Push modified motion paths to hundreds of robots in an
 *    automotive plant. Subtle offset (±2 mm) in weld positions
 *    passes inline vision QC but causes field failures.
 *    Undetectable until customer complaints months later.
 *    Recall cost: hundreds of millions of $.
 *  Recovery: OEM rotates PKI; every controller in the plant
 *  re-provisioned during planned shutdown. Automotive plants
 *  run 24/7; downtime = ~$50k-$200k/hour per line.
 * --------------------------------------------------------- */
