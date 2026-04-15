/*
 * device_update_loop.c
 *
 * FDA-regulated medical-device update loop. Every Class II / Class III
 * device with network connectivity runs some variant of this: fetch
 * update manifest from manufacturer MDM, verify RSA signature against
 * embedded vendor root, stage the image in A/B partitioning, cross-
 * verify before activation, fail-safe on rollback.
 *
 * The RSA verify primitive is in `fda_firmware_signing.c`; this file
 * is the device-side integration including the FDA Premarket
 * Cybersecurity (2023 final guidance) + PATCH Act 2023-mandated SBOM
 * / update-capability checks.
 *
 * Deployed in:
 *   - Medtronic MiniMed insulin pumps, CareLink CGM bridges
 *   - Abbott FreeStyle Libre CGM, MRT portable defibrillators
 *   - Philips Respironics (post-recall), HeartStart defibrillators
 *   - GE CARESCAPE patient monitors, MAC ECG carts
 *   - Siemens Healthineers ACUSON ultrasound, ARTIS interventional
 *   - Stryker / Zimmer Biomet surgical navigation
 *   - Insulet Omnipod, Dexcom G7 cellular bridge
 *   - Baxter SIGMA Spectrum infusion pumps
 *   - Boston Scientific LATITUDE implantable-device home monitors
 */

#include <stdint.h>
#include <stdbool.h>
#include "fda_firmware_signing.h"
#include "device_ab.h"
#include "device_hal.h"


/* Vendor root (RSA-4096) burned into the secure element during
 * factory provisioning. Cannot be rotated in field without a service-
 * depot visit that rewrites the OTP fuses. */
extern const uint8_t VENDOR_ROOT_RSA_PUBKEY_DER[];
extern const size_t  VENDOR_ROOT_RSA_PUBKEY_DER_LEN;


struct update_context {
    uint32_t  current_fw_version;
    uint32_t  anti_rollback_counter;
    uint8_t   device_serial[16];
    bool      in_therapy_session;    /* pump delivering insulin? */
    bool      cellular_backhaul_up;
};


void
device_update_tick(struct update_context *ctx)
{
    /* 1. Device-class policy: never start an update while delivering
     *    therapy. FDA IEC 62304 + IEC 60601-1-2 require verified
     *    safe-state transitions before software change. */
    if (ctx->in_therapy_session) return;
    if (!ctx->cellular_backhaul_up) return;

    /* 2. Poll manufacturer MDM for a signed update manifest. The
     *    manifest is a JSON-LD document countersigned by (a) the
     *    vendor release engineering key and (b) the QA release
     *    officer key — two distinct RSA-4096 keys under the vendor
     *    root hierarchy. This mirrors the IEC 81001-5-1 "independent
     *    release verification" requirement. */
    struct signed_manifest m;
    if (mdm_fetch_manifest(ctx->device_serial, &m) != 0) return;

    if (fda_verify_manifest_rsa_chain(
            &m, VENDOR_ROOT_RSA_PUBKEY_DER,
            VENDOR_ROOT_RSA_PUBKEY_DER_LEN) != 0) {
        audit_log_secure("manifest_rsa_verify_fail",
                          ctx->device_serial, m.version);
        return;
    }

    /* 3. Anti-rollback — FDA "Quality Management System" guidance
     *    explicitly calls out rollback prevention for safety-critical
     *    images. */
    if (m.anti_rollback_counter < ctx->anti_rollback_counter) {
        audit_log_secure("rollback_attempt_blocked",
                          ctx->device_serial, m.version);
        return;
    }

    /* 4. Fetch + verify firmware blob. Blob signature recomputed and
     *    checked against the manifest-listed SHA-384 digest, then the
     *    standalone blob signature verified against the same vendor
     *    RSA chain. Defense-in-depth: manifest and blob must both
     *    agree. */
    if (firmware_fetch_streaming(&m, device_ab_inactive_slot()) != 0) return;

    if (fda_verify_firmware_blob_rsa(
            device_ab_inactive_slot(), &m,
            VENDOR_ROOT_RSA_PUBKEY_DER,
            VENDOR_ROOT_RSA_PUBKEY_DER_LEN) != 0) {
        audit_log_secure("blob_rsa_verify_fail",
                          ctx->device_serial, m.version);
        return;
    }

    /* 5. Stage swap, boot once in "update-candidate" mode, require
     *    self-test pass before committing A/B flip. */
    device_ab_stage_activation(device_ab_inactive_slot());
    device_schedule_reboot_update_candidate();

    /* On next boot: bootloader (itself RSA-signature-verified by the
     * silicon-level secure boot ROM at power-on) runs the candidate
     * image self-test. If self-test asserts any sensor drift /
     * clinical-algorithm validation failure, the A/B swap is
     * rolled back and the device reverts to the previous slot.  If
     * self-test passes, anti-rollback counter is advanced in OTP
     * and the old slot is marked invalid. */
}


/* ---- Breakage ----
 *
 * Every verified medical-device update in the field is a chain from
 * the vendor root RSA-4096 public key (burned in silicon at factory
 * flash) down to the release-engineering + QA-officer leaf signatures
 * on the blob + manifest. A factoring attack against the vendor root
 * lets an attacker push an arbitrary firmware image to every device
 * in the field. The FDA recall apparatus has no primitive for
 * "revoke a trusted-root fuse" at scale — mitigation is physical
 * service of every unit.
 *
 * The patient-safety blast radius is severe: an insulin pump firmware
 * delivering 10x basal rate, a pacemaker firmware forcing
 * bradycardia, an infusion pump firmware ignoring occlusion alarms.
 * This category of cryptographic-root compromise is explicitly in
 * scope for CISA's Medical Device Cybersecurity Joint Advisory line
 * items on post-quantum migration urgency.
 */
