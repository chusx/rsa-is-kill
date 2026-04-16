/*
 * implant_telemetry_session.c
 *
 * Medtronic / Abbott / Biotronik / Boston Scientific CIED
 * (Cardiac Implantable Electronic Device: pacemaker, ICD,
 * CRT-D) wireless telemetry session establishment.
 *
 * Two radios per device:
 *   - 400 MHz MICS (near-field, programmer in clinic)
 *   - 2.4 GHz BLE (home-monitor hub -> remote follow-up)
 *
 * Both terminate in a signed-command channel. The implant
 * has a tiny RSA-2048 verify path (no signing — the implant
 * consumes certs, never issues them). The vendor holds the
 * implantable-device signing key; the clinic programmer holds
 * a short-lived certificate chained to the vendor root.
 *
 * Programmable commands include:
 *   - Therapy reprogramming (pacing thresholds, VT/VF zones)
 *   - Shock-therapy disable
 *   - Antitachycardia pacing rhythm selection
 *   - Firmware activation (staged by prior session)
 *
 * FDA 524B "Ensuring Cybersecurity of Medical Devices" requires
 * authenticated firmware and authenticated command interfaces;
 * the vendor's RSA root is the license-basis trust anchor.
 */

#include <stdint.h>
#include <string.h>
#include "cied.h"

extern const uint8_t VENDOR_IMPLANT_ROOT_PUB[384];  /* RSA-3072 */

#define RADIO_MICS  1
#define RADIO_BLE   2

/* 8-byte device serial is the anti-replay salt; telemetry
 * session transcripts are tiny (battery budget) so nonce is
 * a 16-byte TRNG draw rather than a full epoch. */
struct session_setup_req {
    uint8_t  radio;
    uint8_t  device_serial[8];
    uint8_t  nonce_device[16];          /* implant TRNG         */
};

struct session_setup_resp {
    uint8_t  nonce_device[16];          /* echoed from request  */
    uint8_t  nonce_programmer[16];      /* clinic side          */
    uint32_t epoch;                     /* programmer wallclock */
    uint8_t  prog_cert[1024];   size_t prog_cert_len;
    uint8_t  sig[384];                  /* RSA-PSS SHA-256      */
};

int implant_accept_session(const struct session_setup_req *q,
                           const struct session_setup_resp *r,
                           struct implant_session *s)
{
    if (memcmp(q->nonce_device, r->nonce_device, 16))
        return SS_NONCE;
    if (q->radio != RADIO_MICS && q->radio != RADIO_BLE)
        return SS_RADIO;

    /* Vendor-issued clinic programmer cert, 30-day lifetime. */
    if (x509_chain_verify(r->prog_cert, r->prog_cert_len,
            VENDOR_IMPLANT_ROOT_PUB, sizeof VENDOR_IMPLANT_ROOT_PUB))
        return SS_CHAIN;

    /* Cert carries authorized-procedures extension OID
     * 1.3.6.1.4.1.6569.524B.1 (private vendor arc): bits for
     * reprogram, shock-disable, firmware, diagnostics. */
    uint32_t allowed;
    if (cert_extract_proc_bitmap(r->prog_cert, r->prog_cert_len,
                                 &allowed))
        return SS_PROC_EXT;

    /* Bind session to (nonce_device || nonce_programmer ||
     * device_serial || epoch). */
    uint8_t tbs[16+16+8+4];
    memcpy(tbs, r->nonce_device, 16);
    memcpy(tbs+16, r->nonce_programmer, 16);
    memcpy(tbs+32, q->device_serial, 8);
    write_be32(tbs+40, r->epoch);
    uint8_t h[32]; sha256(tbs, sizeof tbs, h);

    if (verify_with_cert(r->prog_cert, r->prog_cert_len,
                         h, r->sig, sizeof r->sig))
        return SS_SIG;

    s->allowed_procs = allowed;
    s->radio = q->radio;
    memcpy(s->transcript_hash, h, 32);
    return SS_OK;
}

/* =========================================================
 *  Each subsequent command is signed over (transcript_hash
 *  || monotonic-cmd-ctr || command_body). The implant
 *  rejects any command whose ctr <= last seen.
 * ========================================================= */
struct cmd_reprogram {
    uint32_t  ctr;
    uint16_t  therapy_zone_count;
    uint16_t  shock_enable;
    int16_t   pace_amp_mV;
    int16_t   vf_detection_bpm;
    uint16_t  atp_bursts;
    uint8_t   sig[384];
};

int implant_apply_reprogram(struct implant_session *s,
                            const struct cmd_reprogram *c)
{
    if (!(s->allowed_procs & PROC_REPROGRAM)) return SS_DENY;
    if (c->ctr <= s->last_cmd_ctr) return SS_REPLAY;

    uint8_t tbs[32+4+12];
    memcpy(tbs, s->transcript_hash, 32);
    write_be32(tbs+32, c->ctr);
    memcpy(tbs+36, &c->therapy_zone_count, 12);
    uint8_t h[32]; sha256(tbs, sizeof tbs, h);
    if (verify_with_cert_by_session(s, h, c->sig, 384))
        return SS_SIG;

    s->last_cmd_ctr = c->ctr;
    /* Therapy parameters written into the implant's
     * redundant parameter bank with wear-leveled log. */
    return therapy_write(c);
}

/* ---- Harm surface once VENDOR_IMPLANT_ROOT is factored ----
 *  - Mint a clinic-programmer cert with the full
 *    PROC_REPROGRAM | PROC_SHOCK_DISABLE | PROC_FIRMWARE
 *    bitmap, approach any patient (BLE ~10m / MICS ~2m),
 *    complete session, and:
 *      * disable shock therapy on an ICD patient
 *      * induce bradycardia via pacing threshold deltas
 *      * stage attacker firmware for next activation
 *  - Fleet refresh is *surgical*: on the order of 1M
 *    patients per vendor per year new implants, but
 *    already-implanted devices are not field-upgradable
 *    to non-RSA verify paths in most product lines.
 *  - FDA 524B mitigation: manufacturer security advisory;
 *    clinic re-issues cert after vendor rotates root —
 *    but implants already trust the old root with no
 *    rotation path short of explant.
 * --------------------------------------------------------- */
