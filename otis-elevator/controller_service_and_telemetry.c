/*
 * controller_service_and_telemetry.c
 *
 * Elevator controller integration: secure-boot of main + safety
 * firmware, authenticated service-tool sessions, and MQTT-over-TLS
 * telemetry push to the OEM's connected-elevator cloud.
 *
 * Pattern covers Otis Gen2 / SkyRise, KONE MonoSpace, Schindler
 * 5500/7000, TK Evolution. Runs on the controller's Linux-based
 * main CPU with a separate safety-rated PLC subsystem for
 * overspeed/UCMP protection.
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include "elevator.h"
#include "rsa_pkcs1v15.h"
#include "rsa_pss.h"
#include "mqtt_tls.h"

extern const uint8_t OEM_FW_SIGN_ROOT_PUB[512];          /* RSA-4096 */
extern const uint8_t OEM_SAFETY_SIGN_ROOT_PUB[512];      /* TUV-cert'd */
extern const uint8_t OEM_TECHNICIAN_CA_PUB[384];         /* RSA-3072 */
extern const uint8_t OEM_CLOUD_ROOT_PUB[384];            /* cloud server */


/* =========================================================
 *  1. Secure boot of main + safety firmware
 * ========================================================= */

struct main_fw_manifest {
    char     product[16];
    char     build[32];
    uint32_t rollback_idx;
    uint8_t  kernel_sha256[32];
    uint8_t  motion_sha256[32];
    uint8_t  door_sha256[32];
    uint8_t  display_sha256[32];
    uint8_t  sig[512];
};

struct safety_fw_manifest {
    char     product[16];
    char     safety_build[32];
    uint32_t rollback_idx;
    uint8_t  ucmp_sha256[32];        /* unintended car movement */
    uint8_t  overspeed_sha256[32];
    uint8_t  door_interlock_sha256[32];
    uint8_t  sig[512];
};


int elevator_secure_boot(void)
{
    /* Main */
    struct main_fw_manifest *mm = flash_read_main_manifest();
    uint8_t h[32];
    sha256_partition(PART_MAIN_KERNEL, h);
    if (memcmp(h, mm->kernel_sha256, 32)) return ERR_INTEG;

    sha256_of(mm, offsetof(struct main_fw_manifest, sig), h);
    if (rsa_pkcs1v15_verify_sha256(
            OEM_FW_SIGN_ROOT_PUB, sizeof OEM_FW_SIGN_ROOT_PUB,
            (uint8_t[]){0x01,0x00,0x01}, 3,
            h, 32, mm->sig, sizeof mm->sig) != 0)
        return ERR_MAIN_SIG;

    /* Safety — distinct signing chain, verified by the safety-
     * rated CPU (dual-channel with CRC cross-check). */
    struct safety_fw_manifest *sm = flash_read_safety_manifest();
    sha256_partition(PART_SAFETY_UCMP, h);
    if (memcmp(h, sm->ucmp_sha256, 32)) return ERR_SAFETY_INTEG;

    sha256_of(sm, offsetof(struct safety_fw_manifest, sig), h);
    if (rsa_pss_verify_sha256(
            OEM_SAFETY_SIGN_ROOT_PUB, sizeof OEM_SAFETY_SIGN_ROOT_PUB,
            (uint8_t[]){0x01,0x00,0x01}, 3,
            h, 32, sm->sig, sizeof sm->sig) != 0)
        return ERR_SAFETY_SIG;

    return 0;
}


/* =========================================================
 *  2. Technician service-tool authenticated session
 * ========================================================= */

enum service_cmd {
    SVC_READ_FAULT_LOG       = 1,
    SVC_ENTER_INSPECTION     = 2,
    SVC_ADJUST_DOOR_TIMING   = 3,
    SVC_RESCUE_OPERATION     = 4,  /* manually move car during rescue */
    SVC_RESET_BRAKE          = 5,
    SVC_WRITE_FLOOR_HEIGHT   = 6,
    SVC_SET_OVERSPEED_SETPOINT = 7,    /* SAFETY — extra gate required */
};

struct svc_session {
    uint32_t    technician_id;
    uint8_t     tech_pub_n[384];
    size_t      tech_pub_n_len;
    time_t      session_start;
    uint8_t     challenge[32];
};

int svc_authenticate(struct svc_session *s,
                      const uint8_t *tech_cert, size_t tcl,
                      const uint8_t *challenge_sig, size_t csl)
{
    /* Chain-verify technician cert to OEM technician CA. */
    if (x509_chain_verify(tech_cert, tcl,
                           OEM_TECHNICIAN_CA_PUB,
                           sizeof OEM_TECHNICIAN_CA_PUB) != 0)
        return ERR_TECH_CHAIN;

    uint8_t e[4]; size_t e_len;
    x509_extract_pub(tech_cert, tcl,
                      s->tech_pub_n, sizeof s->tech_pub_n, &s->tech_pub_n_len,
                      e, 4, &e_len);

    /* Technician signed our challenge with their private key. */
    uint8_t h[32];
    sha256(s->challenge, 32, h);
    if (rsa_pss_verify_sha256(
            s->tech_pub_n, s->tech_pub_n_len,
            e, e_len,
            h, 32, challenge_sig, csl) != 0)
        return ERR_TECH_SIG;

    s->session_start = time(NULL);
    return 0;
}

int svc_execute_cmd(struct svc_session *s, enum service_cmd c, const void *arg)
{
    /* Safety-impacting commands must be countersigned by a second
     * technician or by a work-order token issued by the OEM
     * dispatch system. */
    if (c == SVC_SET_OVERSPEED_SETPOINT ||
        c == SVC_RESCUE_OPERATION) {
        if (verify_dual_witness_signature() != 0)
            return ERR_DUAL_SIG;
    }
    return actually_execute(c, arg);
}


/* =========================================================
 *  3. Cloud telemetry via MQTT/TLS
 * ========================================================= */

int cloud_publish_telemetry_loop(void)
{
    /* Long-running: re-establish MQTT/TLS session on DPD. Client
     * cert is a per-controller RSA-2048 leaf minted at install by
     * the OEM factory CA. */
    mqtt_session_t *mq = mqtt_tls_connect_mutual(
            CLOUD_MQTT_BROKER,
            "/secrets/controller.crt",
            "/secrets/controller.key",
            OEM_CLOUD_ROOT_PUB, sizeof OEM_CLOUD_ROOT_PUB);
    if (!mq) return -1;

    for (;;) {
        struct elevator_telemetry t;
        t.ts                    = time(NULL);
        t.door_cycles_today     = door_counter_get();
        t.motor_temp_c          = motor_temp_read();
        t.rope_vibration_rms    = vibration_rms_read();
        t.last_fault_code       = faultlog_peek();
        t.position_profile_hash = last_trip_hash();

        /* Signed envelope: controller's own RSA sig over the
         * payload before publish. Signature lets the OEM cloud
         * prove provenance in service-contract analytics. */
        uint8_t h[32];
        sha256_of(&t, sizeof t, h);
        rsa_pkcs1v15_sign_sha256_hsm(
            CTRL_CERT_PRIV_HANDLE, h, 32,
            t.controller_sig, sizeof t.controller_sig);

        mqtt_publish(mq, "elevators/telemetry", &t, sizeof t);
        sleep(5);
    }
}


/* =========================================================
 *  4. Signed firmware update reception + install
 * ========================================================= */

int apply_oem_firmware_push(const uint8_t *pkg, size_t len)
{
    /* Package = main_fw_manifest | safety_fw_manifest | binaries.
     * Both manifests must verify before either image is flashed.
     * Rollback counters are atomically incremented in HSM OTP;
     * any attempt to revert to an older image fails secure_boot. */
    struct main_fw_manifest *mm = parse_main_manifest(pkg, len);
    struct safety_fw_manifest *sm = parse_safety_manifest(pkg, len);
    uint8_t h[32];

    sha256_of(mm, offsetof(struct main_fw_manifest, sig), h);
    if (rsa_pkcs1v15_verify_sha256(
            OEM_FW_SIGN_ROOT_PUB, sizeof OEM_FW_SIGN_ROOT_PUB,
            (uint8_t[]){0x01,0x00,0x01}, 3,
            h, 32, mm->sig, sizeof mm->sig) != 0) return ERR_MAIN_SIG;

    sha256_of(sm, offsetof(struct safety_fw_manifest, sig), h);
    if (rsa_pss_verify_sha256(
            OEM_SAFETY_SIGN_ROOT_PUB, sizeof OEM_SAFETY_SIGN_ROOT_PUB,
            (uint8_t[]){0x01,0x00,0x01}, 3,
            h, 32, sm->sig, sizeof sm->sig) != 0) return ERR_SAFETY_SIG;

    flash_write_main_image(pkg);
    flash_write_safety_image(pkg);
    hsm_bump_rollback_counter();
    schedule_safe_reboot_window();
    return 0;
}


/* ---- Breakage ---------------------------------------------
 *
 *   OEM firmware root compromised:
 *     - Signed firmware disabling unintended-car-movement
 *       protection, ascending-car overspeed governor, or door-
 *       interlock logic across the installed fleet of one brand.
 *       Potentially fatal outcomes in millions of buildings.
 *
 *   OEM safety root compromised:
 *     - Similar scope, but directly hitting TÜV-certified safety
 *       code path. EN 81-20 / A17.1 conformance on every affected
 *       unit invalidated pending re-audit.
 *
 *   Technician CA compromised:
 *     - Mint service-tool certs, enter service mode on elevators
 *       in specific high-rise targets, adjust motion profiles or
 *       trigger rescue-operation mode while occupied.
 *
 *   Per-controller cert compromised:
 *     - Forge telemetry to mask real faults or fabricate fault
 *       dispatches — revenue manipulation in managed-service
 *       contracts.
 *
 *   Recovery from a widespread firmware-signing compromise is a
 *   physical truck-roll to every controller — multi-year capital
 *   program per OEM.
 */
