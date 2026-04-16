/*
 * sdls_tc_session.c
 *
 * CCSDS Space Data Link Security (SDLS, CCSDS 355.0-B-2) session
 * establishment + telecommand dispatch for a spacecraft. The SDLS
 * Security Association (SA) is bootstrapped with an RSA key-
 * transport (TC Channel Service, CCSDS 232.0-B-4) using the
 * spacecraft's on-board RSA-2048 public key, published in the
 * mission Flight Operations Procedure (FOP).
 *
 * Missions using SDLS or variants:
 *   - ESA: Galileo 2nd-gen, JUICE, ExoMars, Hera
 *   - NASA: Artemis Gateway, LRO (RSA-OAEP key wrap)
 *   - JAXA: MMX
 *   - Commercial: SpaceX Dragon (internal variant),
 *     Starlink, OneWeb, Amazon Kuiper
 *
 * The ground station (MOC/FDS) RSA-signs TC frames to prevent
 * unauthorized commanding. Once the SA is established, the
 * AES-GCM channel handles integrity + confidentiality; but
 * key rotation every 2^32 frames is again RSA-wrapped.
 */

#include <stdint.h>
#include <string.h>
#include "ccsds.h"

extern const uint8_t SPACECRAFT_RSA_PUB[384];    /* on-board NVM  */
extern const uint8_t MOC_SIGNING_PUB[384];       /* ground PKI    */

struct sdls_sa_init {
    uint16_t  sa_id;                   /* Security Association ID */
    uint8_t   key_id;
    uint8_t   acs;                     /* auth cipher suite:
                                          0x01 = AES-GCM-128     */
    uint8_t   iv[12];                  /* initial IV              */
    uint8_t   aes_key_wrapped[256];    /* RSA-OAEP(session_key,
                                          SPACECRAFT_RSA_PUB)    */
    uint8_t   moc_sig[384];           /* RSA-PSS over above     */
};

int onboard_accept_sa(const struct sdls_sa_init *init)
{
    /* Verify MOC signature over the SA init TLV. */
    uint8_t h[32];
    sha256_of(init, offsetof(struct sdls_sa_init, moc_sig), h);
    if (rsa_pss_verify_sha256(MOC_SIGNING_PUB, 384,
            (uint8_t[]){1,0,1}, 3, h, 32,
            init->moc_sig, sizeof init->moc_sig))
        return SDLS_AUTH_FAIL;

    /* RSA-OAEP unwrap session key using on-board private key. */
    uint8_t session_key[16];
    size_t klen = 16;
    if (rsa_oaep_decrypt_onboard(
            init->aes_key_wrapped, 256,
            session_key, &klen))
        return SDLS_UNWRAP_FAIL;

    return sa_install(init->sa_id, init->acs,
                      session_key, klen, init->iv);
}

/* =========================================================
 *  TC (telecommand) frame dispatch — runs over the SA
 *  channel after session establishment. AES-GCM tags are
 *  checked before dispatch; but the SA itself was rooted
 *  in the RSA bootstrap.
 * ========================================================= */

enum tc_function {
    TC_SAFE_MODE              = 0x01,
    TC_THRUSTER_FIRE          = 0x02,
    TC_PAYLOAD_POWER          = 0x03,
    TC_SOLAR_ARRAY_DEPLOY     = 0x04,
    TC_FW_UPLOAD_START        = 0x10,
    TC_DEORBIT_INITIATE       = 0x80,
};

struct tc_frame {
    uint16_t  scid;                    /* spacecraft ID            */
    uint16_t  vcid;                    /* virtual channel          */
    uint32_t  frame_seq;
    uint8_t   tc_function;
    uint8_t   params[64];
    uint8_t   aes_gcm_tag[16];
};

int onboard_tc_dispatch(const struct tc_frame *f,
                         uint16_t sa_id)
{
    if (!sa_aes_gcm_verify(sa_id, f, sizeof(*f) - 16,
                           f->aes_gcm_tag))
        return TC_AUTH_FAIL;
    if (f->frame_seq <= sa_last_seq(sa_id)) return TC_REPLAY;
    sa_seq_bump(sa_id, f->frame_seq);

    switch (f->tc_function) {
    case TC_SAFE_MODE:          return spacecraft_safe_mode();
    case TC_THRUSTER_FIRE:      return thruster_fire(f->params);
    case TC_PAYLOAD_POWER:      return payload_pdu(f->params);
    case TC_SOLAR_ARRAY_DEPLOY: return sadm_deploy(f->params);
    case TC_FW_UPLOAD_START:    return fw_upload_begin(f->params);
    case TC_DEORBIT_INITIATE:   return deorbit_sequence(f->params);
    default: return TC_UNKNOWN;
    }
}

/* ---- On-orbit kill-chain ----------------------------------
 *  MOC_SIGNING_PUB factored:
 *    Forge SA-init -> inject a new SA under attacker-chosen
 *    AES key. Then issue arbitrary TC frames including:
 *      * TC_THRUSTER_FIRE with no abort window = irreversible
 *        orbit change / collision maneuver / reentry.
 *      * TC_FW_UPLOAD = persistent OBC compromise.
 *      * TC_DEORBIT on a 10-ton LEO asset = forced reentry.
 *    Kessler-cascade risk if LEO constellation targeted.
 *
 *  SPACECRAFT_RSA_PUB factored:
 *    Decrypt any intercepted SA-init -> derive session key
 *    -> decrypt all subsequent TC traffic. Also: forge new
 *    SA-init with attacker session key since the on-board
 *    decrypt is reversible to sign.
 *
 *  Recovery: upload new on-board RSA keys via... the
 *  compromised TC channel. Bootstrap paradox. Physical
 *  recovery is not possible for most missions.
 * --------------------------------------------------------- */
