/*
 * ecu_fill_and_mission_load.c
 *
 * MIDS Electronic Crypto Unit (ECU) firmware self-verify, fill-
 * device (SKL/NGLD-M) handshake, and signed mission-load receive
 * path. Runs on the terminal's crypto MCU inside a tamper-
 * responding enclosure. PowerPC / ARM typical.
 *
 * Cleared content only — this is the public-sketch crypto
 * envelope, not the classified waveform, key derivation, or
 * keying-material structures.
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include "mids.h"
#include "rsa_pss.h"
#include "rsa_pkcs1v15.h"
#include "aes_keywrap.h"

extern const uint8_t NSA_FW_ROOT_PUB[512];       /* Service/Agency */
extern const uint8_t KMF_PROVISIONING_PUB[512];  /* Key Mgmt Facility */
extern const uint8_t MISSION_PLAN_ROOT_PUB[384]; /* Service MP-PKI */


/* =========================================================
 *  1. ECU firmware self-verify
 * ========================================================= */

struct ecu_fw_manifest {
    char      platform[16];
    char      build[32];
    uint32_t  rollback_idx;
    uint8_t   waveform_sha256[32];
    uint8_t   comsec_sha256[32];
    uint8_t   tempest_filter_sha256[32];
    uint8_t   sig[512];                 /* RSA-4096 PKCS#1v1.5 */
};

int ecu_fw_self_verify(void)
{
    struct ecu_fw_manifest *m = flash_read_manifest();
    if (m->rollback_idx < tamper_nvm_rollback()) return ERR_ROLLBACK;

    uint8_t h[32];
    sha256_partition(PART_COMSEC, h);
    if (memcmp(h, m->comsec_sha256, 32)) return ERR_COMSEC;

    sha256_of(m, offsetof(struct ecu_fw_manifest, sig), h);
    return rsa_pkcs1v15_verify_sha256(
        NSA_FW_ROOT_PUB, sizeof NSA_FW_ROOT_PUB,
        (uint8_t[]){0x01,0x00,0x01}, 3,
        h, 32, m->sig, sizeof m->sig);
}


/* =========================================================
 *  2. Fill-device (SKL / NGLD-M) handshake
 *
 *  The fill device presents a KMF-signed credential naming the
 *  terminal serial it is authorised to fill. The ECU challenges
 *  the fill device, which signs the challenge with its KMF-issued
 *  RSA key before any symmetric key material is transferred.
 * ========================================================= */

struct fill_device_credential {
    char      fill_serial[16];
    char      authorised_terminal[16];
    uint32_t  not_after;
    uint8_t   fill_cert[1536];
    size_t    cert_len;
    uint8_t   sig[512];          /* KMF signature over this record */
};

int ecu_begin_fill_session(const struct fill_device_credential *cred)
{
    if (strncmp(cred->authorised_terminal,
                 ecu_serial(), 16))
        return ERR_WRONG_TARGET;

    uint32_t now = trusted_time();
    if (now > cred->not_after) return ERR_CRED_EXPIRED;

    uint8_t h[32];
    sha256_of(cred, offsetof(struct fill_device_credential, sig), h);
    if (rsa_pss_verify_sha256(
            KMF_PROVISIONING_PUB, sizeof KMF_PROVISIONING_PUB,
            (uint8_t[]){0x01,0x00,0x01}, 3,
            h, 32, cred->sig, sizeof cred->sig) != 0)
        return ERR_KMF_SIG;

    /* Challenge-response with the fill device's own cert, chained
     * to KMF. Fill device signs our nonce. */
    uint8_t nonce[32];
    rng_bytes(nonce, sizeof nonce);
    uint8_t resp_sig[512]; size_t rs_len;
    if (fill_device_sign_challenge(nonce, sizeof nonce,
                                    resp_sig, &rs_len) != 0)
        return ERR_FILL_RESP;

    uint8_t n[384], e[4];
    size_t n_len, e_len;
    x509_extract_pub(cred->fill_cert, cred->cert_len,
                     n, sizeof n, &n_len, e, sizeof e, &e_len);
    sha256(nonce, sizeof nonce, h);
    if (rsa_pss_verify_sha256(n, n_len, e, e_len,
                              h, 32, resp_sig, rs_len) != 0)
        return ERR_FILL_SIG;

    open_fill_channel();
    return 0;
}


/* =========================================================
 *  3. OTAR envelope (MIDS-JTRS / Link 22)
 *
 *  Symmetric keys (TEKs / TrEKs) arrive wrapped under a pre-
 *  placed KEK. Envelope outer integrity is RSA-signed by KMF.
 * ========================================================= */

struct otar_envelope {
    uint32_t  kmf_seq;
    uint32_t  issued_ts;
    uint16_t  key_type;              /* TEK / TrEK / IFF / GPS-cryptovar */
    uint16_t  wrapped_len;
    uint8_t   wrapped[256];          /* AES-KW under KEK */
    uint8_t   sig[512];
};

static uint32_t last_kmf_seq;

int ecu_apply_otar(const struct otar_envelope *e)
{
    if (e->kmf_seq <= last_kmf_seq) return ERR_REPLAY;

    uint8_t h[32];
    sha256_of(e, offsetof(struct otar_envelope, sig), h);
    if (rsa_pss_verify_sha256(
            KMF_PROVISIONING_PUB, sizeof KMF_PROVISIONING_PUB,
            (uint8_t[]){0x01,0x00,0x01}, 3,
            h, 32, e->sig, sizeof e->sig) != 0)
        return ERR_OTAR_SIG;

    uint8_t key[64];
    size_t out_len = sizeof key;
    if (tamper_aes_unwrap(KEK_SLOT,
                           e->wrapped, e->wrapped_len,
                           key, &out_len) != 0) return ERR_UNWRAP;

    tamper_install_keymat(e->key_type, key, out_len);
    secure_wipe(key, sizeof key);
    last_kmf_seq = e->kmf_seq;
    return 0;
}


/* =========================================================
 *  4. Mission-plan / load-set ingestion
 * ========================================================= */

struct mission_load {
    char      airframe[8];
    char      sortie_id[24];
    uint32_t  takeoff_window_start;
    uint32_t  takeoff_window_end;
    uint32_t  body_len;
    uint8_t   body[65536];           /* waypoints, IFF codes, EW profiles */
    uint8_t   sig[384];
};

int avionics_load_mission(const struct mission_load *ml)
{
    uint32_t now = trusted_time();
    if (now > ml->takeoff_window_end) return ERR_STALE;

    uint8_t h[32];
    sha256_of(ml, offsetof(struct mission_load, sig), h);
    return rsa_pss_verify_sha256(
        MISSION_PLAN_ROOT_PUB, sizeof MISSION_PLAN_ROOT_PUB,
        (uint8_t[]){0x01,0x00,0x01}, 3,
        h, 32, ml->sig, sizeof ml->sig);
}


/* ---- Breakage ---------------------------------------------
 *
 *  KMF provisioning root factored:
 *    - Forged SKL credentials admit attacker-keyed fills;
 *      attacker-controlled TEKs take hold. Real-time SIGINT on
 *      Link 16 tracks, IFF, engagement assignments — NATO
 *      tactical edge visibility.
 *
 *  NSA/service fw root factored:
 *    - Signed ECU firmware that leaks key schedules, weakens
 *      entropy, or exfils keystreams via TEMPEST side-channels.
 *
 *  Mission-plan root factored:
 *    - Signed mission loads with altered no-strike / ROE data,
 *      wrong IFF codes. Blue-on-blue risk.
 */
