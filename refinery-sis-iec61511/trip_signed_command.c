/*
 * trip_signed_command.c
 *
 * Emerson DeltaV SIS / Honeywell Safety Manager / Siemens
 * SIMATIC Safety / Schneider Tricon Safety Logic Solver
 * signed engineering-change and forced-trip channel.
 *
 * IEC 61511 SIL-3 demand-mode SIS. Any change to the safety
 * application (cause-and-effect matrix, trip setpoints,
 * bypasses, MoC-approved parameter changes) is transported
 * from the Engineering Workstation to the Logic Solver via a
 * signed "Safety-Configuration-Change Record" (SCCR). The
 * SCCR is signed by:
 *   (a) the Authorized Function Engineer's smartcard cert
 *   (b) the plant's Functional Safety Assessor (FSA) cert
 *   (c) the OEM product-release cert (for firmware only)
 *
 * The Logic Solver enforces IEC 61511-1 §11.6.1 cause-and-
 * effect immutability during the proof-test interval; the
 * only legitimate way to rewrite it is a signed SCCR
 * accompanied by a MoC record ID (in 61511 §17.2.2).
 */

#include <stdint.h>
#include <string.h>
#include "sis.h"

extern const uint8_t OEM_PRODUCT_ROOT_PUB[384];    /* Emerson etc. */
extern const uint8_t PLANT_SAFETY_ROOT_PUB[384];   /* Site CA     */

#define SCCR_MAGIC        "SCCR01"

enum sccr_kind {
    SCCR_CAE_MATRIX     = 1,  /* cause-and-effect table update   */
    SCCR_SETPOINT       = 2,  /* trip threshold tweak            */
    SCCR_BYPASS         = 3,  /* temporary bypass (shall expire) */
    SCCR_FORCED_TRIP    = 4,  /* deliberate trip from console    */
    SCCR_FIRMWARE       = 5,  /* Logic Solver FW update          */
};

struct sccr_header {
    char       magic[6];                /* "SCCR01"              */
    uint8_t    kind;                    /* enum sccr_kind        */
    uint16_t   plant_id;
    char       unit_id[16];             /* "FCCU-1", "HDS-2"     */
    char       moc_ref[24];             /* "MOC-2024-000891"     */
    uint32_t   not_before;
    uint32_t   not_after;               /* bypasses have ~8h     */
    uint32_t   body_len;
};

struct sccr_signed {
    struct sccr_header hdr;
    uint8_t    body[8192];              /* CAE/setpoint blob     */
    /* Two signers always. Firmware requires OEM too. */
    uint8_t    eng_cert[2048]; size_t eng_cert_len;
    uint8_t    fsa_cert[2048]; size_t fsa_cert_len;
    uint8_t    eng_sig[384];
    uint8_t    fsa_sig[384];
    uint8_t    oem_sig[384];            /* kind==SCCR_FIRMWARE   */
    uint8_t    oem_sig_present;
};

/* SIL-3 engineering-change acceptance on Logic Solver.
 * Called in the maintenance partition; the safety runtime
 * partition keeps executing the current application until
 * commit. This is a 2oo3-voter partition — each voter must
 * independently accept the SCCR. */
int sis_accept_sccr(const struct sccr_signed *s)
{
    if (memcmp(s->hdr.magic, SCCR_MAGIC, 6)) return SCCR_MAGIC_BAD;
    if (s->hdr.body_len > sizeof s->body)    return SCCR_TOO_BIG;
    if (now() < s->hdr.not_before || now() > s->hdr.not_after)
        return SCCR_WINDOW;

    /* The engineer cert must chain to PLANT_SAFETY_ROOT and
     * carry extendedKeyUsage OID 1.3.6.1.4.1.61511.1 (our
     * local assignment for "Authorized Function Engineer"). */
    if (x509_chain_verify_eku(s->eng_cert, s->eng_cert_len,
            PLANT_SAFETY_ROOT_PUB, sizeof PLANT_SAFETY_ROOT_PUB,
            "1.3.6.1.4.1.61511.1"))
        return SCCR_ENG_CERT;

    if (x509_chain_verify_eku(s->fsa_cert, s->fsa_cert_len,
            PLANT_SAFETY_ROOT_PUB, sizeof PLANT_SAFETY_ROOT_PUB,
            "1.3.6.1.4.1.61511.2"))
        return SCCR_FSA_CERT;

    /* Signatures are over {hdr || body}. */
    uint8_t h[32];
    sha256_of_header_and_body(s, h);

    if (verify_with_cert(s->eng_cert, s->eng_cert_len,
                         h, s->eng_sig, sizeof s->eng_sig))
        return SCCR_ENG_SIG;
    if (verify_with_cert(s->fsa_cert, s->fsa_cert_len,
                         h, s->fsa_sig, sizeof s->fsa_sig))
        return SCCR_FSA_SIG;

    if (s->hdr.kind == SCCR_FIRMWARE) {
        if (!s->oem_sig_present) return SCCR_MISSING_OEM;
        if (rsa_pss_verify_sha256(OEM_PRODUCT_ROOT_PUB, 384,
                (uint8_t[]){1,0,1}, 3, h, 32,
                s->oem_sig, sizeof s->oem_sig))
            return SCCR_OEM_SIG;
    }

    /* MoC cross-check: the Logic Solver queries the Plant Safety
     * Registry over a read-only back-channel for moc_ref. Without
     * a matching open MoC, the SCCR is rejected regardless of
     * signatures — administrative gate independent of crypto. */
    if (!moc_registry_open(s->hdr.moc_ref)) return SCCR_NO_MOC;

    return sis_stage_change(&s->hdr, s->body, s->hdr.body_len);
}

/* ---- Kinetic consequence surface -------------------------
 *  Plant safety root RSA factored:
 *    - Forge AFE+FSA signatures; ship SCCR_BYPASS with
 *      not_after = 8h for the demand-mode HIPPS at a reactor
 *      feed. Pressure-relief interlock silenced; runaway
 *      reaction -> explosion / vapor cloud (Bhopal-class).
 *    - Forge SCCR_SETPOINT raising trip setpoints past design
 *      envelope; Logic Solver no longer actuates on real
 *      process excursions.
 *    - Forge SCCR_CAE_MATRIX removing rows/columns; entire
 *      groups of safety instrumented functions become inert.
 *
 *  OEM product root RSA factored:
 *    - SCCR_FIRMWARE: replace Logic Solver firmware across
 *      every site running that OEM product; SIS silently
 *      executes attacker logic.
 *
 *  Recovery: each SIS is under a Safety Requirements
 *  Specification and IEC 61511 proof-test plan; key rotation
 *  is a re-certification event. Realistic timeline = months
 *  per plant, often driven by turnaround schedules; in the
 *  meantime regulator (OSHA/HSE/BSEE) imposes operating
 *  restrictions or shutdown.
 * --------------------------------------------------------- */
