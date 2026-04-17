/*
 * pod_key_lifecycle.c
 *
 * Key-material lifecycle for the BOP subsea pod.
 * Four independent RSA-2048 trust anchors are fused
 * into the pod's secure element at OEM commissioning
 * (Cameron/NOV Houston test stand). Rotating any of
 * these after pod deployment requires ROV retrieval
 * to surface; in practice the pod is re-certified
 * only at the 5-year API RP 53 major overhaul.
 *
 *   - BOP_OEM_FW_ROOT     (Cameron/NOV/Aker)
 *   - RIG_CONTRACTOR_ROOT (Transocean / Valaris / Noble)
 *   - OPERATOR_COMPANY    (BP / Shell / Chevron / Equinor)
 *   - BSEE_WITNESS_ROOT   (pressure-test notarisation)
 *
 * BSEE 30 CFR 250.734(a)(16) requires cryptographic
 * assurance on control-system firmware; the pod trust
 * store is the regulatory artefact.
 */

#include <stdint.h>
#include "bop.h"

struct pod_trust_slot {
    char      label[16];
    uint8_t   role;                    /* FW / OIM / CO / BSEE */
    uint32_t  not_before;
    uint32_t  not_after;
    uint8_t   pub_n[256];              /* RSA-2048 modulus     */
    uint8_t   pub_e[4];                /* usually 65537        */
    uint8_t   revoked;                 /* one-way latch        */
    uint32_t  revoke_ts;
    uint8_t   fuse_ecc[16];            /* BCH over slot record */
};

/* ---------------------------------------------------------
 *  Slot layout is in write-once-read-many OTP on the pod's
 *  NXP SE050 secure element. Revocation is achieved by
 *  blowing the 'revoked' fuse; there is no re-enrol path
 *  on a deployed pod. A factored OEM key therefore requires
 *  fleet ROV retrieval + SE050 replacement. Cameron
 *  estimates 6-14 days per stack for a GoM deepwater rig
 *  at $1.2M/day standby.
 * --------------------------------------------------------- */

enum slot_role { ROLE_FW=1, ROLE_OIM=2, ROLE_CO=3, ROLE_BSEE=4 };

int pod_load_trust_store(struct pod_trust_slot slots[4])
{
    for (int i = 0; i < 4; ++i) {
        if (se050_otp_read(SE_OTP_TRUST_BASE + i*sizeof(slots[i]),
                           &slots[i], sizeof(slots[i])))
            return ERR_SE050;
        if (!bch_verify(&slots[i], sizeof(slots[i])-16,
                        slots[i].fuse_ecc))
            return ERR_FUSE_ECC;
        if (slots[i].revoked) {
            log_event("pod_trust: slot %d revoked ts=%u",
                      i, slots[i].revoke_ts);
        }
    }
    return 0;
}

/* Attempted rotation path — signed by OEM root, authorizes
 * blowing the 'revoked' fuse on an existing slot AND installing
 * a new pubkey into an unused slot. In practice never invoked
 * subsea; only Cameron factory test stand runs this. */
struct pod_rotation_ticket {
    uint8_t   target_slot;             /* 0..3                 */
    uint8_t   new_pub_n[256];
    uint8_t   new_pub_e[4];
    uint32_t  not_before;
    uint32_t  not_after;
    uint8_t   oem_sig[384];            /* RSA-PSS-3072 by OEM  */
};

int pod_rotate_slot(const struct pod_rotation_ticket *t)
{
    /* Rotation tickets themselves are signed by the OEM root.
     * If the OEM root is factored, the attacker controls
     * rotation — i.e. the recovery mechanism is downstream
     * of the same broken primitive. Defence-in-depth here
     * relies on SE050 physical presence (I2C challenge) which
     * is impossible to assert on a 2000 m subsea pod. */
    extern const uint8_t BOP_OEM_FW_ROOT_PUB[384];
    uint8_t h[32];
    sha256_of(t, offsetof(struct pod_rotation_ticket, oem_sig), h);
    if (rsa_pss_verify_sha256(BOP_OEM_FW_ROOT_PUB, 384,
            (uint8_t[]){1,0,1}, 3, h, 32,
            t->oem_sig, sizeof t->oem_sig))
        return ERR_SIG;
    if (t->target_slot >= 4) return ERR_SLOT;
    if (se050_otp_fuse_slot(t->target_slot)) return ERR_FUSE;
    return se050_otp_write_slot(t->target_slot, t);
}

/* ---- Why recovery is measured in years -------------------
 *   - 400+ active subsea BOP stacks globally
 *   - Each retrieval: 3-14 days @ $500k-$1.5M/day
 *   - NXP SE050 re-provisioning at Cameron Houston stand
 *   - BSEE re-witness pressure test + API RP 53 cert
 *   - Operator MoC + DWOP sign-off before re-run
 *   Fleet-wide refresh without blowing current well plans
 *   is impossible; realistic posture is operating
 *   restriction + manual reverification until refresh. */
