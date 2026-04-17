/*
 * rg152_digital_asset_manifest.c
 *
 * NRC Regulatory Guide 1.152 Rev 4 / IEC 61513 / IEC 60880 Class-1E
 * digital I&C asset manifest structure. Every "digital asset"
 * (controller firmware, FPGA bitstream, engineering configuration,
 * OS image for a qualified HMI) in a nuclear I&C system carries
 * a manifest signed under the vendor-qualified product key AND
 * co-signed by the licensee's responsible engineer.
 *
 * Vendors in scope:
 *   - Framatome TELEPERM XS / TXS (EPR, AP1000)
 *   - Westinghouse Common Q (AP1000)
 *   - Mitsubishi MELTAC
 *   - Rolls-Royce SPINLINE 3 (EPR2, SMR)
 *   - Doosan ENFORCE (APR1400)
 *   - Triconex Tricon CX (non-SRP Class-1E, defence-in-depth)
 *
 * Under RG 1.152 R4 Section C.2.2, the "integrity of configuration
 * items" throughout the lifecycle is a license-basis requirement;
 * the signature chain IS the regulator-accepted evidence.
 */

#include <stdint.h>
#include <string.h>
#include "iec61513.h"

#define IAEA_FINGERPRINT_LEN  32

struct da_manifest {
    /* ----- identity ----- */
    char       plant_unit[16];      /* "VG3-1", "VC-1"          */
    char       system_id[8];        /* "RPS","ESFAS","CPC"      */
    char       asset_id[24];        /* ALWR-unique identifier   */
    char       vendor[16];
    char       product[32];
    uint16_t   div;                 /* redundant division A..D  */

    /* ----- content ----- */
    uint8_t    image_sha256[32];
    uint32_t   qualification_class; /* 1E | supporting | non-1E */
    uint32_t   sil_category;        /* IEC 61513 / 61226 Cat A-C*/
    uint32_t   cs_package_rev;      /* CSN / engineering rev    */

    /* ----- licensee 10 CFR 50.59 cross-ref ----- */
    char       mod_package_id[16];  /* "EC-2024-00213"          */
    char       ser_ref[16];         /* NRC SER citation          */
    uint32_t   not_before;
    uint32_t   not_after;

    /* ----- signatures ----- */
    uint8_t    vendor_cert[2048]; size_t vendor_cert_len;
    uint8_t    rea_cert[2048];    size_t rea_cert_len;  /* Resp. Eng. */
    uint8_t    iss_cert[2048];    size_t iss_cert_len;  /* ISI/IV&V   */
    uint8_t    vendor_sig[384];     /* RSA-PSS SHA256, 3072-bit  */
    uint8_t    rea_sig[384];
    uint8_t    iss_sig[384];        /* Independent V&V signature */
};

/* Loader on the divisional hardened platform (TELEPERM/Common Q
 * engineering tool) prior to deployment into the qualified
 * target. Digital Asset Management System logs the signed
 * manifest hash into the plant's permanent record. */
int da_manifest_accept(const struct da_manifest *m)
{
    extern const uint8_t VENDOR_PRODUCT_ROOT_PUB[384];
    extern const uint8_t LICENSEE_SAFETY_ROOT_PUB[384];
    extern const uint8_t INDEPENDENT_VV_ROOT_PUB[384];

    if (now() < m->not_before || now() > m->not_after)
        return DA_WINDOW;
    if (m->qualification_class == 0 /* 1E */
        && m->sil_category != 2 /* Cat A */)
        return DA_CAT_MISMATCH;

    /* Three independent chains. Defense in depth for the trust
     * graph — but all three are RSA, all three collapse together
     * under a classical factoring break. */
    if (x509_chain_verify(m->vendor_cert, m->vendor_cert_len,
            VENDOR_PRODUCT_ROOT_PUB, sizeof VENDOR_PRODUCT_ROOT_PUB))
        return DA_VENDOR_CHAIN;
    if (x509_chain_verify(m->rea_cert, m->rea_cert_len,
            LICENSEE_SAFETY_ROOT_PUB, sizeof LICENSEE_SAFETY_ROOT_PUB))
        return DA_REA_CHAIN;
    if (x509_chain_verify(m->iss_cert, m->iss_cert_len,
            INDEPENDENT_VV_ROOT_PUB, sizeof INDEPENDENT_VV_ROOT_PUB))
        return DA_ISS_CHAIN;

    uint8_t h[32];
    sha256_of(m, offsetof(struct da_manifest, vendor_cert), h);

    if (verify_with_cert(m->vendor_cert, m->vendor_cert_len,
                         h, m->vendor_sig, sizeof m->vendor_sig))
        return DA_VENDOR_SIG;
    if (verify_with_cert(m->rea_cert, m->rea_cert_len,
                         h, m->rea_sig, sizeof m->rea_sig))
        return DA_REA_SIG;
    if (verify_with_cert(m->iss_cert, m->iss_cert_len,
                         h, m->iss_sig, sizeof m->iss_sig))
        return DA_ISS_SIG;

    /* 10 CFR 50.59 administrative check — the mod package must be
     * in the plant's DAMS with status "RELEASED_TO_FIELD". */
    if (!dams_is_released(m->mod_package_id)) return DA_MOC;

    iaea_fingerprint_log(m->asset_id, m->image_sha256);
    return DA_ACCEPT;
}

/* ---- Radiological consequence path --------------------------
 *  Factored VENDOR_PRODUCT_ROOT (Framatome/Westinghouse/...):
 *    Replace RPS/ESFAS firmware across the installed base of a
 *    product line. Silent defeat of reactor trip / containment
 *    isolation / ECCS actuation. An attacker with precursor
 *    physical-initiator access (design-basis accident pre-
 *    cursor) avoids the I&C trip. NRC emergency order;
 *    regulator-driven outage of every unit running that
 *    product; replacement silicon is years out.
 *
 *  Factored LICENSEE_SAFETY_ROOT:
 *    Forge Responsible Engineering Authority signatures on
 *    arbitrary configuration changes. In-plant only, but
 *    evades the electronic MoC audit trail.
 *
 *  Factored INDEPENDENT_VV_ROOT:
 *    Removes the independent-V&V gate; an insider with vendor
 *    + licensee access can push unreviewed code.
 *
 *  License basis = signatures. Revocation posture is regulator-
 *  driven operating restriction + manual configuration baseline
 *  reverification until qualified PQ replacement is available.
 * ------------------------------------------------------------- */
