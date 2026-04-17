/*
 * rtu_firmware_and_dnp3_sav5.c
 *
 * Pipeline Remote Terminal Unit firmware receive + DNP3-SAv5 Update
 * Key Change path. Runs on the RTU MCU (ARM Cortex-A on Emerson
 * ROC800L, PowerPC on Bristol ControlWave, TriCore on Schneider
 * SCADAPack). Configured per operator conformance to API 1164 3rd
 * edition + TSA-SD Pipeline 2021-02.
 *
 * This is only the firmware + DNP3 key-rotation path. The DNP3-SA
 * per-message HMAC loop (Critical ASDU challenge/response) is in
 * dnp3_sa_runtime.c (not shown).
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include "rtu.h"
#include "rsa_pkcs1v15.h"
#include "rsa_oaep.h"
#include "rsa_pss.h"
#include "hmac.h"

extern const uint8_t VENDOR_FW_ROOT_PUB[512];     /* RSA-4096 */
extern const uint8_t MASTER_DNP3_PUB[384];        /* Master Station RSA-3072 */
extern const uint8_t OPERATOR_API1164_ROOT_PUB[384]; /* for LDS packet sigs */


/* =========================================================
 *  1. Firmware self-verify at boot
 * ========================================================= */

struct rtu_fw_manifest {
    char      product[16];        /* "ROC800L-v3.6" */
    char      build[32];
    uint32_t  rollback_idx;
    uint8_t   kernel_sha256[32];
    uint8_t   app_sha256[32];
    uint8_t   fb_logic_sha256[32]; /* FunctionBlock / IEC 61131-3 */
    uint8_t   sig[512];
};

int rtu_fw_self_verify(void)
{
    struct rtu_fw_manifest *m = flash_read_manifest();
    if (m->rollback_idx < otp_read_rollback()) return ERR_ROLLBACK;

    uint8_t h[32];
    sha256_partition(PART_KERNEL, h);
    if (memcmp(h, m->kernel_sha256, 32)) return ERR_KERNEL;
    sha256_partition(PART_APP, h);
    if (memcmp(h, m->app_sha256, 32))    return ERR_APP;
    sha256_partition(PART_FB_LOGIC, h);
    if (memcmp(h, m->fb_logic_sha256, 32)) return ERR_FB;

    sha256_of(m, offsetof(struct rtu_fw_manifest, sig), h);
    return rsa_pkcs1v15_verify_sha256(
        VENDOR_FW_ROOT_PUB, sizeof VENDOR_FW_ROOT_PUB,
        (uint8_t[]){0x01,0x00,0x01}, 3,
        h, 32, m->sig, sizeof m->sig);
}


/* =========================================================
 *  2. DNP3 Secure Authentication v5 — Update Key Change
 *
 *  Per IEEE 1815-2012: Master wraps a new session-level Update Key
 *  for this outstation using the outstation's RSA public key
 *  (OAEP-SHA256). Master signs the whole Update-Key-Change
 *  message with Master's private key.
 * ========================================================= */

struct dnp3_update_key_change {
    uint16_t  user_number;
    uint32_t  key_change_seq;         /* monotonic */
    uint32_t  key_change_method;      /* 3 = ASYM_RSA_OAEP_SHA256 */
    uint16_t  wrapped_key_len;
    uint8_t   wrapped_key[384];       /* RSA-3072 OAEP-wrapped 32B */
    uint16_t  master_sig_len;
    uint8_t   master_sig[384];        /* RSA-3072 PSS-SHA256 over the above */
};

int dnp3_handle_update_key_change(const struct dnp3_update_key_change *uk)
{
    /* 1. Verify Master signed the entire message. */
    uint8_t h[32];
    sha256_of(uk, offsetof(struct dnp3_update_key_change, master_sig_len), h);
    if (rsa_pss_verify_sha256(
            MASTER_DNP3_PUB, sizeof MASTER_DNP3_PUB,
            (uint8_t[]){0x01,0x00,0x01}, 3,
            h, 32, uk->master_sig, uk->master_sig_len) != 0)
        return ERR_MASTER_SIG;

    /* 2. Monotonic replay guard. */
    if (uk->key_change_seq <= last_key_change_seq()) return ERR_REPLAY;

    /* 3. Unwrap the new Update Key with our RSA private key
     *    (held in the secure element). */
    uint8_t new_update_key[32];
    size_t out_len = sizeof new_update_key;
    if (rsa_oaep_decrypt_sha256_se(
            OUTSTATION_PRIV_HANDLE,
            uk->wrapped_key, uk->wrapped_key_len,
            new_update_key, &out_len) != 0 || out_len != 32)
        return ERR_UNWRAP;

    dnp3_install_update_key(uk->user_number, new_update_key);
    set_last_key_change_seq(uk->key_change_seq);
    secure_wipe(new_update_key, sizeof new_update_key);

    /* From this point forward, per-ASDU HMACs use the new key. */
    return 0;
}


/* =========================================================
 *  3. LDS (leak-detection) packet outbound — signed
 * =========================================================
 *
 *  API 1130 / CPM requires real-time hydraulic data from flow
 *  computers to be delivered to the LDS with integrity. A
 *  tampered or suppressed packet can delay leak detection.
 *  The RTU signs each minute-aggregated packet.
 */

struct lds_packet {
    uint32_t  rtu_id;
    uint32_t  ts;
    double    upstream_pressure_psig;
    double    downstream_pressure_psig;
    double    flow_bph;
    double    temperature_f;
    uint8_t   sig[384];
};

int lds_push_minute_packet(void)
{
    struct lds_packet p;
    p.rtu_id = rtu_identity();
    p.ts     = (uint32_t)time(NULL);
    p.upstream_pressure_psig  = pt_read(SENSOR_UPSTREAM);
    p.downstream_pressure_psig= pt_read(SENSOR_DOWNSTREAM);
    p.flow_bph                = fm_read(SENSOR_MAINLINE);
    p.temperature_f           = rtd_read(SENSOR_TFLUID);

    uint8_t h[32];
    sha256_of(&p, offsetof(struct lds_packet, sig), h);
    rsa_pss_sign_sha256_se(
        RTU_LDS_PRIV_HANDLE,
        h, 32, p.sig, sizeof p.sig);

    return dnp3_publish_to_cpm(&p, sizeof p);
}


/* =========================================================
 *  4. Firmware OTA from vendor / operator PKI
 * ========================================================= */

int apply_rtu_firmware_push(const uint8_t *pkg, size_t len)
{
    struct rtu_fw_manifest *m = parse_rtu_manifest(pkg, len);
    uint8_t h[32];
    sha256_of(m, offsetof(struct rtu_fw_manifest, sig), h);

    if (rsa_pkcs1v15_verify_sha256(
            VENDOR_FW_ROOT_PUB, sizeof VENDOR_FW_ROOT_PUB,
            (uint8_t[]){0x01,0x00,0x01}, 3,
            h, 32, m->sig, sizeof m->sig) != 0)
        return ERR_FW_SIG;

    /* Operator-co-sign: API 1164 3rd-edition control requires the
     * end-user operator to additionally sign that this build is
     * change-management approved for this specific pipeline asset. */
    if (verify_operator_cosig(pkg, len,
            OPERATOR_API1164_ROOT_PUB,
            sizeof OPERATOR_API1164_ROOT_PUB) != 0)
        return ERR_OPERATOR_COSIG;

    flash_write_partition(PART_APP, pkg, len);
    otp_bump_rollback();
    schedule_maintenance_window_reboot();
    return 0;
}


/* ---- Breakage ---------------------------------------------
 *
 *   VENDOR_FW_ROOT factored:
 *     - Signed firmware pushed to compressor-station controllers
 *       that trips an entire gas-transmission corridor. Heating-
 *       season mass outage for downstream LDCs. Or drives pumps
 *       past MAOP → rupture.
 *
 *   MASTER_DNP3_PUB factored:
 *     - Attacker completes a valid DNP3-SAv5 Update Key Change as
 *       the Master, then commands close-block-valve / change-
 *       setpoint on mainline block valves. TRITON-class direct
 *       control of kinetic infrastructure.
 *
 *   OPERATOR_API1164_ROOT factored:
 *     - LDS packet sigs forged; leak alarms suppressed while a
 *       spill accumulates. Multi-billion environmental liability.
 *       Custody-transfer events forged — fraud on >$10M/day
 *       fiscal metering.
 */
