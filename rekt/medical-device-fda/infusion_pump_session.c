/*
 * infusion_pump_session.c
 *
 * BD Alaris / Baxter Spectrum IQ / ICU Medical Plum 360 infusion
 * pump authenticated session for remote drug-library + firmware
 * push from the hospital pharmacy / biomedical-engineering server.
 *
 * FDA 524B requires authenticated firmware + authenticated config
 * for networked infusion devices. The RSA dependency is in the
 * TLS mutual-auth from the pump to the Drug Library Server (DLS)
 * and in the signed firmware manifest (see fda_firmware_signing.c).
 *
 * An attacker who factors the hospital's medical-device PKI
 * can push a modified drug library that removes hard-limit
 * guardrails on critical drugs — the Stuxnet-for-hospitals
 * scenario.
 */

#include <stdint.h>
#include <string.h>
#include "infusion.h"

extern const uint8_t HOSPITAL_MEDDEV_ROOT_PUB[384];

/* Drug-library entry. The CQI (Continuous Quality Improvement)
 * drug library is pushed from BD HealthSight / ICU Medical
 * MedNet to every pump in the facility. Each drug has hard and
 * soft limits programmed by pharmacy. */
struct drug_entry {
    char      drug_name[64];         /* "HEParin 25000 units/500mL" */
    char      concentration[32];     /* "50 units/mL"               */
    float     hard_limit_max;        /* mL/h — pump refuses above   */
    float     hard_limit_min;
    float     soft_limit_max;        /* nurse gets warning           */
    float     soft_limit_min;
    uint8_t   care_area;             /* ICU / MedSurg / Peds / NICU */
};

struct drug_library_manifest {
    char      hospital_id[16];
    uint32_t  library_version;
    uint32_t  drug_count;
    struct drug_entry drugs[512];
    uint8_t   pharmacist_cert[2048]; size_t pharmacist_cert_len;
    uint8_t   sig[384];              /* RSA-PSS SHA256             */
};

int pump_accept_drug_library(const struct drug_library_manifest *m)
{
    if (m->library_version <= pump_current_lib_version())
        return PUMP_ERR_ROLLBACK;

    if (x509_chain_verify(m->pharmacist_cert, m->pharmacist_cert_len,
            HOSPITAL_MEDDEV_ROOT_PUB,
            sizeof HOSPITAL_MEDDEV_ROOT_PUB))
        return PUMP_ERR_CHAIN;

    uint8_t h[32];
    sha256_of(m, offsetof(struct drug_library_manifest, pharmacist_cert), h);
    if (verify_with_cert(m->pharmacist_cert, m->pharmacist_cert_len,
                         h, m->sig, sizeof m->sig))
        return PUMP_ERR_SIG;

    /* Commit to pump NV storage; reboot to activate. */
    return pump_install_library(m);
}

/* ---- Attack path once HOSPITAL_MEDDEV_ROOT factored --------
 *   Forge a drug library that raises Heparin hard_limit_max
 *   from 2000 units/h to 99999 units/h. Push to every pump
 *   in the facility over Wi-Fi. Nurse programs an order at
 *   a dose the pump would normally reject; patient receives
 *   a lethal overdose with no guardrail alarm.
 *
 *   Alternatively: remove a drug entry entirely so the pump
 *   runs in "no library" mode = no hard limits for any drug.
 *
 *   The same cert chain also authenticates the pump's mTLS
 *   session to the electronic health record (Epic Cerner);
 *   a forged device cert can inject false infusion-complete
 *   events into the MAR (Medication Administration Record).
 *
 *   FDA 524B recall posture: manufacturer issues a recall /
 *   safety notice; biomedical engineering must physically
 *   touch each pump to reprovisioning trust store. ~100-500
 *   pumps per hospital; ~5000 hospitals in the US alone.
 * --------------------------------------------------------- */
