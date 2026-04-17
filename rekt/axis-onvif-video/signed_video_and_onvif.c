/*
 * signed_video_and_onvif.c
 *
 * Per-frame video signing (Axis Signed Video / C2PA-compatible)
 * and ONVIF WS-Security-signed configuration handling. Runs on the
 * camera's embedded Linux / Axis ARTPEC SoC, Ambarella, HiSilicon,
 * Novatek, or equivalent.
 *
 * Only the signing-plane is modelled here. H.264/265 encoder,
 * RTSP/SRTP streamer, and analytics are elsewhere.
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include "camera.h"
#include "rsa_pss.h"

extern const uint8_t OEM_FW_ROOT_PUB[512];
extern const uint8_t CAMERA_ISSUING_CA_PUB[384]; /* per-camera leaf issuer */


/* =========================================================
 *  1. Per-GOP signed-video record
 *
 *  Signing every frame is too expensive. Signed Video / C2PA
 *  sign once per Group Of Pictures over a Merkle root covering
 *  the GOP's frame hashes + embedded timestamp + GNSS (when
 *  fitted for mobile / body-worn).
 * ========================================================= */

struct signed_gop {
    char      camera_serial[32];
    uint32_t  stream_id;
    uint32_t  gop_seq;              /* monotonic per stream */
    uint32_t  gop_start_ts_utc;
    uint32_t  n_frames;
    uint8_t   frame_merkle_root[32];
    /* Motion-metadata + GNSS (optional). For PTZ cameras the
     * pan/tilt/zoom readings go here. For body-worn, GNSS +
     * IMU attitude. All of it is covered by the signature. */
    int32_t   lat_e7, lon_e7;
    uint16_t  pan_deg_x10, tilt_deg_x10, zoom_x10;
    uint8_t   device_cert[1536];
    size_t    cert_len;
    uint8_t   sig[384];             /* RSA-3072 PSS-SHA256 */
};

int build_and_sign_gop(uint32_t stream_id, uint32_t gop_seq,
                       const uint8_t frame_hashes[][32],
                       uint32_t n_frames,
                       struct signed_gop *out)
{
    memset(out, 0, sizeof *out);
    strncpy(out->camera_serial, device_serial(),
            sizeof out->camera_serial);
    out->stream_id        = stream_id;
    out->gop_seq          = gop_seq;
    out->gop_start_ts_utc = gnss_disciplined_time();
    out->n_frames         = n_frames;
    merkle_root_sha256(frame_hashes, n_frames, out->frame_merkle_root);
    ptz_readings(&out->pan_deg_x10, &out->tilt_deg_x10, &out->zoom_x10);
    gnss_position_e7(&out->lat_e7, &out->lon_e7);
    device_export_cert(out->device_cert, sizeof out->device_cert,
                       &out->cert_len);

    uint8_t h[32];
    sha256_of(out, offsetof(struct signed_gop, sig), h);
    return rsa_pss_sign_sha256_se(
        DEVICE_SIGNING_KEY,
        h, 32, out->sig, sizeof out->sig);
}


/* =========================================================
 *  2. Verifier side — VMS, evidence platform, court-admission
 * ========================================================= */

int verify_gop(const struct signed_gop *g, const uint8_t frame_hashes[][32])
{
    /* Re-derive Merkle root from recovered frame hashes (which
     * come out of the stored .mp4 via the saved frame boundary
     * table). */
    uint8_t computed[32];
    merkle_root_sha256(frame_hashes, g->n_frames, computed);
    if (memcmp(computed, g->frame_merkle_root, 32))
        return ERR_FRAME_TAMPER;

    /* Chain the per-camera cert to the OEM issuing CA. */
    if (x509_chain_verify(g->device_cert, g->cert_len,
                          CAMERA_ISSUING_CA_PUB,
                          sizeof CAMERA_ISSUING_CA_PUB) != 0)
        return ERR_CHAIN;

    uint8_t n[384], e[4];
    size_t n_len, e_len;
    x509_extract_pub(g->device_cert, g->cert_len,
                     n, sizeof n, &n_len, e, sizeof e, &e_len);

    uint8_t h[32];
    sha256_of(g, offsetof(struct signed_gop, sig), h);
    return rsa_pss_verify_sha256(n, n_len, e, e_len,
                                 h, 32, g->sig, sizeof g->sig);
}


/* =========================================================
 *  3. ONVIF WS-Security-signed config message handler
 *
 *  ONVIF Device Management + Imaging + PTZ services accept SOAP
 *  calls with `<wsse:BinarySecurityToken>` + an XMLDSig signature
 *  over the SOAP body. The camera verifies against the enterprise
 *  NVR/VMS cert.
 * ========================================================= */

int onvif_handle_signed_config(const char *soap_xml, size_t len)
{
    struct wsse_parsed p;
    if (wsse_parse(soap_xml, len, &p) != 0) return ERR_PARSE;

    /* p.signer_cert chains to the enterprise admin-CA registered
     * with this camera at commissioning (Genetec, Milestone,
     * Avigilon, or customer-owned). */
    if (x509_chain_verify(p.signer_cert, p.signer_cert_len,
                          installed_admin_ca(),
                          installed_admin_ca_len()) != 0)
        return ERR_ADMIN_CHAIN;

    /* XMLDSig over the `Body` element, canonicalised per W3C EXC
     * C14N. Underlying signature primitive is RSA-SHA256. */
    if (xmldsig_verify_enveloped(soap_xml, len, &p) != 0)
        return ERR_SIG;

    /* Action dispatch: PTZ, set analytic rules, firmware update
     * trigger, user-account management. Firmware-update requests
     * require an additional OEM-level signed image (see below). */
    return onvif_dispatch_action(&p);
}


/* =========================================================
 *  4. Firmware receive path
 * ========================================================= */

int camera_apply_fw_update(const uint8_t *pkg, size_t len)
{
    struct fw_manifest {
        char product[16]; char build[32]; uint32_t rollback_idx;
        uint8_t image_sha256[32]; uint8_t sig[512];
    } *m = parse_fw_manifest(pkg, len);

    if (m->rollback_idx < otp_read_rollback()) return ERR_ROLLBACK;

    uint8_t h[32];
    sha256_partition(PART_APP_CANDIDATE, h);
    if (memcmp(h, m->image_sha256, 32)) return ERR_IMG_HASH;

    sha256_of(m, offsetof(struct fw_manifest, sig), h);
    if (rsa_pss_verify_sha256(
            OEM_FW_ROOT_PUB, sizeof OEM_FW_ROOT_PUB,
            (uint8_t[]){0x01,0x00,0x01}, 3,
            h, 32, m->sig, sizeof m->sig) != 0)
        return ERR_FW_SIG;

    promote_partition_and_reboot();
    return 0;
}


/* ---- Breakage ---------------------------------------------
 *
 *   OEM_FW_ROOT factored:
 *     - Signed firmware pushed to millions of cameras. Mirai-
 *       class botnet + latent ISR capability. Or: silently
 *       disable the per-GOP signing so all post-compromise
 *       video fails evidentiary admission.
 *
 *   CAMERA_ISSUING_CA factored:
 *     - Forge signed GOPs for cameras that don't exist, or
 *       replace real GOPs in an archive with signed forgeries.
 *       Surveillance video evidence admissibility collapses.
 *
 *   Admin / ONVIF signer CA factored:
 *     - Remote config push to arbitrary cameras — PTZ them
 *       away from an incident, disable recording to the VMS,
 *       create backdoor admin accounts.
 *
 *   ALPR / LPR signing root factored (adjacent path):
 *     - Forged plate-reads place vehicles at scenes; wanted
 *       vehicles mis-routed; mass privacy + false-accusation
 *       harm.
 */
