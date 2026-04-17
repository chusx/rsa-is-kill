/*
 * turbine_fw_and_iec61400_25.c
 *
 * Wind-turbine main controller firmware self-verify, safety-
 * controller separate-chain verify, and IEC 61400-25 MMS mutual-
 * auth to park SCADA. Pattern matches Vestas VMP-7000 series, SGRE
 * WebWPS, GE Mark VIe, Goldwind Fortune controllers. Runs on
 * PowerPC / ARM embedded Linux in the hub + tower cabinet.
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include "turbine.h"
#include "iec61850.h"
#include "rsa_pkcs1v15.h"
#include "rsa_pss.h"

extern const uint8_t OEM_FW_ROOT_PUB[512];            /* RSA-4096 */
extern const uint8_t OEM_SAFETY_SIGN_ROOT_PUB[512];   /* TÜV SIL2 chain */
extern const uint8_t OPERATOR_SCADA_CA_PUB[384];
extern const uint8_t TSO_GRID_SERVICES_ROOT_PUB[384];


/* =========================================================
 *  1. Main controller firmware self-verify at boot
 * ========================================================= */

struct wtc_fw_manifest {
    char      oem[16];
    char      model[16];
    char      build[32];
    uint32_t  rollback_idx;
    uint8_t   kernel_sha256[32];
    uint8_t   yaw_sha256[32];
    uint8_t   pitch_sha256[32];
    uint8_t   converter_if_sha256[32];
    uint8_t   cms_sha256[32];             /* condition-monitoring */
    uint8_t   sig[512];
};

int wtc_fw_self_verify(void)
{
    struct wtc_fw_manifest *m = flash_read_manifest();
    if (m->rollback_idx < hsm_rollback()) return ERR_ROLLBACK;

    uint8_t h[32];
    sha256_partition(PART_KERNEL, h);
    if (memcmp(h, m->kernel_sha256, 32)) return ERR_CORRUPT;

    sha256_of(m, offsetof(struct wtc_fw_manifest, sig), h);
    return rsa_pkcs1v15_verify_sha256(
        OEM_FW_ROOT_PUB, sizeof OEM_FW_ROOT_PUB,
        (uint8_t[]){0x01,0x00,0x01}, 3,
        h, 32, m->sig, sizeof m->sig);
}


/* =========================================================
 *  2. Safety controller (separate CPU, SIL 2) firmware verify
 *
 *  The pitch-brake / overspeed / e-stop logic lives on a
 *  separately-rated CPU. IEC 61508 requires independence: even
 *  a main-controller firmware-key compromise must not
 *  authoritatively reach the safety path.
 * ========================================================= */

struct safety_fw_manifest {
    char      build[32];
    uint32_t  rollback_idx;
    uint8_t   overspeed_sha256[32];
    uint8_t   pitch_brake_sha256[32];
    uint8_t   yaw_brake_sha256[32];
    uint8_t   sig[512];
};

int safety_fw_self_verify(void)
{
    struct safety_fw_manifest *m = safety_flash_manifest();
    if (m->rollback_idx < safety_rollback_otp()) return ERR_ROLLBACK;

    uint8_t h[32];
    sha256_of(m, offsetof(struct safety_fw_manifest, sig), h);
    return rsa_pss_verify_sha256(
        OEM_SAFETY_SIGN_ROOT_PUB, sizeof OEM_SAFETY_SIGN_ROOT_PUB,
        (uint8_t[]){0x01,0x00,0x01}, 3,
        h, 32, m->sig, sizeof m->sig);
}


/* =========================================================
 *  3. IEC 61400-25 MMS session to park SCADA
 * ========================================================= */

mms_session_t *wtc_scada_connect(void)
{
    /* Mutual TLS. Per-turbine RSA-2048 leaf issued by operator's
     * plant PKI (often backed by Vault or EJBCA). IEC 61850
     * MMS rides on top. */
    return mms_tls_connect_mutual(
        PARK_SCADA_HOST,
        "/factory/turbine.crt", "/factory/turbine.key",
        OPERATOR_SCADA_CA_PUB, sizeof OPERATOR_SCADA_CA_PUB);
}

void wtc_publish_one_second_telemetry(mms_session_t *m)
{
    struct wtg_sample s;
    s.ts_utc       = (uint32_t)time(NULL);
    s.p_active_mw  = converter_read_p_mw();
    s.q_mvar       = converter_read_q();
    s.wind_ms      = anemo_read_ms();
    s.rotor_rpm    = encoder_rpm();
    s.pitch_deg    = pitch_avg_deg();
    s.yaw_deg      = yaw_deg();
    s.gearbox_oil_c= rtd_gearbox();
    s.nacelle_vib  = vib_rms();

    /* MMS provides SetDataValues with per-object access control.
     * A signed-session plus per-object ACL on the SCADA side is
     * the trust model. */
    mms_set_data(m, "WTG1.MeasureMX.Q.instMag.mag.f", &s.q_mvar);
    mms_set_data(m, "WTG1.MeasureMX.TotW.instMag.mag.f", &s.p_active_mw);
    /* ...additional logical nodes... */
}


/* =========================================================
 *  4. Grid-services dispatch from TSO / ISO
 *
 *  Signed dispatch messages tell the plant to adjust active/
 *  reactive power setpoints as part of ancillary-service
 *  obligations (frequency response, voltage support, FFR).
 *  Plant-controller forwards per-turbine setpoints.
 * ========================================================= */

struct grid_dispatch {
    uint32_t  dispatch_id;            /* monotonic per TSO */
    uint32_t  effective_ts;
    uint32_t  duration_s;
    uint8_t   service_type;           /* 1=AGC 2=FFR 3=VOLT 4=CURTAIL */
    int32_t   p_setpoint_mw;
    int32_t   q_setpoint_mvar;
    uint8_t   tso_cert[1024];
    size_t    cert_len;
    uint8_t   sig[384];
};

static uint32_t last_dispatch_id;

int plant_accept_grid_dispatch(const struct grid_dispatch *d)
{
    if (d->dispatch_id <= last_dispatch_id) return ERR_REPLAY;

    if (x509_chain_verify(d->tso_cert, d->cert_len,
                          TSO_GRID_SERVICES_ROOT_PUB,
                          sizeof TSO_GRID_SERVICES_ROOT_PUB) != 0)
        return ERR_CHAIN;

    uint8_t n[384], e[4];
    size_t n_len, e_len;
    x509_extract_pub(d->tso_cert, d->cert_len,
                     n, sizeof n, &n_len, e, sizeof e, &e_len);

    uint8_t h[32];
    sha256_of(d, offsetof(struct grid_dispatch, sig), h);
    if (rsa_pss_verify_sha256(n, n_len, e, e_len,
                              h, 32, d->sig, sizeof d->sig) != 0)
        return ERR_SIG;

    /* Plausibility: setpoints within plant capability + interconnect
     * agreement. Rate-limit changes; protect against spiked setpoints
     * that destabilise local voltage. */
    if (!setpoints_within_envelope(d->p_setpoint_mw, d->q_setpoint_mvar))
        return ERR_ENVELOPE;

    last_dispatch_id = d->dispatch_id;
    distribute_setpoints_to_fleet(d->p_setpoint_mw, d->q_setpoint_mvar);
    return 0;
}


/* ---- Breakage ---------------------------------------------
 *
 *  OEM_FW_ROOT factored (Vestas/SGRE/GE/Goldwind):
 *    - Fleet-wide signed firmware that (a) trips every turbine
 *      on a simultaneous cue — hundreds of GW vanish from the
 *      grid, triggering cascading under-frequency blackouts
 *      across interconnects; or (b) subtly alters pitch/yaw
 *      so rotors overspeed into structural failure, ejecting
 *      multi-tonne blades.
 *
 *  OEM_SAFETY_SIGN_ROOT factored:
 *    - The defence-in-depth safety CPU firmware is compromised.
 *      TÜV/SIL-2 certification on every turbine invalid pending
 *      re-audit; operators must park the fleet under manual-
 *      monitored operation.
 *
 *  TSO grid-services root factored (ERCOT/CAISO/NG ESO/Nordic):
 *    - Forged dispatch during frequency events; fleet disconnects
 *      at the worst moment, amplifying a grid-crisis into a
 *      full blackout à la 2003 Northeast US or 2006 UCTE.
 *
 *  Operator SCADA CA factored:
 *    - Plant-internal MMS integrity lost; attackers inject
 *      setpoints directly at individual turbines to induce
 *      resonant torque events / mechanical failure.
 */
