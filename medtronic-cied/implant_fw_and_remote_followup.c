/*
 * implant_fw_and_remote_followup.c
 *
 * Implantable cardiac device firmware-update receive path, in-clinic
 * programmer pairing, and bedside-monitor remote-follow-up upload.
 * Pattern matches Medtronic Azure/Percepta/Cobalt, Abbott
 * Gallant/Assurity, Boston Scientific Resonate/Accolade, Biotronik
 * Rivacor/Edora.
 *
 * The implant MCU is power-constrained (Cortex-M0 typical; only a
 * few MHz when the radio is on). RSA verify is done on the
 * infrequent path (firmware load, programmer pairing) only; runtime
 * pacing + sensing is untouched by crypto.
 */

#include <stdint.h>
#include <string.h>
#include "implant.h"
#include "rsa_pss.h"
#include "rsa_pkcs1v15.h"

extern const uint8_t OEM_FW_ROOT_PUB[384];          /* RSA-3072 */
extern const uint8_t OEM_PROGRAMMER_CA_PUB[384];    /* RSA-3072 */
extern const uint8_t OEM_CLOUD_CA_PUB[384];         /* bedside upload */


/* =========================================================
 *  1. In-clinic programmer pairing — challenge/response
 *
 *  The programmer presents a cert chained to OEM programmer CA.
 *  The implant issues a 16-byte random challenge; the programmer
 *  signs it with its private key. Implant verifies, then unlocks
 *  the programming interface for a bounded session.
 * ========================================================= */

struct programmer_session {
    uint8_t   challenge[16];
    uint32_t  opened_ts_local;
    uint8_t   programmer_n[384];
    size_t    programmer_n_len;
    uint8_t   programmer_e[4];
    size_t    programmer_e_len;
    uint16_t  session_idle_remaining_s;
};

int pair_with_programmer(struct programmer_session *s,
                         const uint8_t *prog_cert, size_t cert_len,
                         const uint8_t *challenge_sig, size_t sig_len)
{
    /* 1. Chain programmer cert to OEM programmer-issuing CA. */
    if (x509_chain_verify(prog_cert, cert_len,
                          OEM_PROGRAMMER_CA_PUB,
                          sizeof OEM_PROGRAMMER_CA_PUB) != 0)
        return ERR_PROG_CHAIN;

    x509_extract_pub(prog_cert, cert_len,
                     s->programmer_n, sizeof s->programmer_n,
                     &s->programmer_n_len,
                     s->programmer_e, sizeof s->programmer_e,
                     &s->programmer_e_len);

    /* 2. Verify programmer's signature over our (just-issued) challenge. */
    uint8_t h[32];
    sha256(s->challenge, sizeof s->challenge, h);
    if (rsa_pss_verify_sha256(
            s->programmer_n, s->programmer_n_len,
            s->programmer_e, s->programmer_e_len,
            h, 32, challenge_sig, sig_len) != 0)
        return ERR_PROG_SIG;

    /* 3. Policy: open the write-capable programming window for 10
     *    minutes idle-timeout. Read-only diagnostic remains open
     *    to any programmer that passes step 1 (clinician workflow
     *    accommodation). */
    s->opened_ts_local = implant_clock();
    s->session_idle_remaining_s = 600;
    unlock_programming_interface();
    return 0;
}


/* =========================================================
 *  2. Firmware update receive (via paired programmer OR via
 *  bedside-monitor relay)
 * ========================================================= */

struct implant_fw_manifest {
    char      model[16];
    char      build[24];
    uint32_t  rollback_idx;
    uint32_t  image_bytes;
    uint8_t   image_sha256[32];
    /* Feature hash: the set of therapeutic features the update
     * activates/changes. Programmer displays this to the clinician;
     * unchanged features must match the field hash. */
    uint8_t   features_sha256[32];
    uint8_t   sig[384];
};

int implant_apply_firmware(const uint8_t *img, uint32_t img_len,
                           const struct implant_fw_manifest *m)
{
    if (!programmer_session_open_for_write() &&
        !bedside_remote_trigger_valid())
        return ERR_NO_WRITE_CONTEXT;

    if (m->rollback_idx < otp_rollback()) return ERR_ROLLBACK;
    if (m->image_bytes != img_len)        return ERR_SIZE;

    uint8_t h[32];
    sha256(img, img_len, h);
    if (memcmp(h, m->image_sha256, 32))   return ERR_IMG_HASH;

    sha256_of(m, offsetof(struct implant_fw_manifest, sig), h);
    if (rsa_pkcs1v15_verify_sha256(
            OEM_FW_ROOT_PUB, sizeof OEM_FW_ROOT_PUB,
            (uint8_t[]){0x01,0x00,0x01}, 3,
            h, 32, m->sig, sizeof m->sig) != 0)
        return ERR_FW_SIG;

    /* Belt-and-braces: a pacing-therapy implant must never lose
     * the "keep pacing during update" property. Dual-bank flash:
     * write to inactive bank, verify, swap on next cycle idle. */
    flash_write_inactive_bank(img, img_len);
    request_swap_at_next_idle();
    return 0;
}


/* =========================================================
 *  3. Bedside-monitor nightly upload
 * ========================================================= */

int bedside_upload_nightly_episode_log(void)
{
    /* Bedside monitor opens mutual TLS to OEM cloud and relays
     * the implant's signed episode log. The implant's own sig is
     * the authoritative evidence; TLS is the transport. */
    mqtt_session_t *m = mqtt_tls_connect_mutual(
        OEM_CLOUD_BROKER,
        "/bedside/monitor.crt", "/bedside/monitor.key",
        OEM_CLOUD_CA_PUB, sizeof OEM_CLOUD_CA_PUB);
    if (!m) return -1;

    struct implant_episode_log {
        char     patient_dev_serial[16];
        uint32_t episode_seq;
        uint32_t onset_ts;
        uint32_t offset_ts;
        uint16_t rate_bpm;
        uint8_t  rhythm_class;   /* 0=SR 1=PVC 2=NSVT 3=VT 4=VF */
        uint8_t  shock_delivered;
        uint8_t  sig[256];       /* implant RSA-2048 PSS over above */
    } log;
    implant_read_and_sign_latest_episode(&log);

    mqtt_publish(m, "cied/episodes", &log, sizeof log);
    mqtt_close(m);
    return 0;
}


/* ---- Breakage ---------------------------------------------
 *
 *  OEM_FW_ROOT factored (Medtronic/Abbott/BSci/Biotronik):
 *    - Signed firmware loadable by any programmer or bedside
 *      monitor. Scale depends on how OTA-remote-trigger the vendor
 *      has rolled out — some models update only in-clinic, others
 *      automatically overnight. Worst case: millions of implants
 *      updated within days to a firmware that delivers
 *      inappropriate shocks / silent pacing failure. Mass
 *      casualty with a latency of days-to-months as patients'
 *      arrhythmia episodes trigger the payload.
 *
 *  OEM_PROGRAMMER_CA factored:
 *    - Attacker approaches target within telemetry range with
 *      a forged programmer credential and reprograms pacing
 *      thresholds / detection zones / therapy. Targeted
 *      assassination capability against individuals.
 *
 *  OEM_CLOUD_CA factored:
 *    - Silent suppression of real arrhythmia uploads (patient
 *      deaths from undetected rhythms go un-flagged to the
 *      follow-up cardiologist). Forged false uploads drive
 *      unnecessary clinic visits + reprogramming.
 */
