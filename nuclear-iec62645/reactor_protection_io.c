/*
 * reactor_protection_io.c
 *
 * IEC 62645 / IEC 61513 / IEEE 7-4.3.2 compliant cybersecurity
 * envelope around the Reactor Protection System (RPS) I/O path in a
 * modern PWR/BWR nuclear unit. Surrounds the safety I/O bus with
 * RSA-authenticated messaging for configuration, engineering-tool
 * access, and cross-division diverse-actuation coordination. The RSA
 * primitives are in `nuclear_rsa_sign.c`.
 *
 * Deployed in (representative):
 *   - Westinghouse Common-Q / Common-Qualified (AP1000: Vogtle 3/4,
 *     Haiyang, Sanmen; Cernavodă retrofit)
 *   - Framatome TELEPERM XS / SPPA-T2000 (EPR: Olkiluoto 3, Flamanville 3,
 *     Hinkley Point C, Sizewell C)
 *   - Mitsubishi MELTAC-Nplus (APWR, US-APWR)
 *   - Rolls-Royce SMR digital RPS (UK GDA ongoing 2026)
 *   - CNP-1000 / HPR-1000 (Hualong One) at Fuqing, Karachi K-2/K-3
 *   - Atmea1, KLT-40S (Akademik Lomonosov, Akademik Kurchatov SMR)
 */

#include <stdint.h>
#include "nuclear_rsa_sign.h"
#include "rps_io.h"

/* Regulatory posture: IEC 62645 demands authentication on all
 * configuration / engineering tool messages reaching the RPS; IEC
 * 61513 safety-classification keeps the *safety function* path
 * deterministic (no crypto in the 50ms protection trip loop).  RSA
 * therefore lives on the management/engineering plane, not on the
 * safety trip plane itself — but authorization of ANY change to the
 * trip-plane parameters (setpoints, block bits, calibration
 * constants) flows through the RSA envelope. */


enum rps_mgmt_msg {
    RPS_CFG_READ_SETPOINTS        = 1,
    RPS_CFG_WRITE_SETPOINTS       = 2,
    RPS_CAL_COEFFICIENTS_UPDATE   = 3,
    RPS_DIVERSE_ACT_VOTING_CFG    = 4,
    RPS_CALIBRATION_TEST_ENABLE   = 5,
    RPS_ENGINEERING_ACCESS_GRANT  = 6,
};


struct rps_signed_msg {
    uint32_t  msg_type;
    uint32_t  seq;
    uint32_t  ts_utc;
    uint32_t  payload_len;
    uint8_t   payload[4096];
    uint8_t   operator_cert_der[2048];
    size_t    operator_cert_len;
    uint8_t   signature[512];    /* RSA-4096 PSS-SHA384 */
};


/* Called on every packet arriving at the RPS from the engineering
 * workstation / DCS side (separate physical network per IEC 60880
 * D1 defense-in-depth; one-way diode from DCS to RPS is common). */
int
rps_on_mgmt_ingress(struct rps_signed_msg *m)
{
    /* 1. Chain to the plant's Nuclear CA (operated by the utility's
     *    Cyber Security Incident Response Team + approved by the
     *    national regulator: NRC, ONR, ASN, CNSC, STUK, NSR).  Root
     *    material is RSA-4096 on HSMs in the Tech Support Center,
     *    with quorum-attended ceremonies for key rotation (paralleling
     *    NEI 13-10 + 10 CFR 73.54 cyber program requirements in the
     *    US). */
    if (nuclear_verify_cert_chain_rsa(
            m->operator_cert_der, m->operator_cert_len) != 0)
        return rps_audit_and_reject(m, "chain-verify-fail");

    /* 2. Authorization check: operator cert must carry the OID for
     *    the requested msg_type.  Setpoint writes require a TWO-person
     *    rule — message must carry two independent signatures, one
     *    by a licensed operator and one by a plant engineer. */
    if (!rps_cert_authorized_for(m->operator_cert_der, m->msg_type))
        return rps_audit_and_reject(m, "op-not-authorized");

    /* 3. RSA-PSS signature verify. Per IEC 62645 + IAEA NSS 17-T,
     *    replay-protection via monotonic seq+ts. */
    if (nuclear_rsa_pss_verify(m) != 0)
        return rps_audit_and_reject(m, "rsa-sig-fail");

    /* 4. Apply. All applies are mirrored to the Independent Safety
     *    Engineering audit log (required for INSAG-25 safety
     *    case), replicated to the regulator-readable log bus. */
    return rps_apply_mgmt_msg(m);
}


/* ---- Breakage ----
 *
 * The plant Nuclear CA is the authorization root for every
 * engineering-plane change to the RPS. A factoring break of its
 * RSA-4096 root lets an attacker (with plant-network access — the
 * scenario NRC/ONR threat models do cover, even for isolated
 * control networks, after Stuxnet / Sandworm incidents) issue
 * authenticated setpoint changes to the protection system — raise
 * trip thresholds, defeat diverse actuation, or enable calibration
 * test mode during power operation. The defense-in-depth layers
 * (physical data diodes, air gap, IEC 60880 D1/D2/D3 separation)
 * reduce but do not eliminate the exposure; the cryptographic
 * envelope is specifically the layer that distinguishes authorized
 * from unauthorized configuration writes. This is why IAEA NSS 17-T
 * and the NRC RIS 2015-07 post-quantum lookahead explicitly name
 * nuclear cybersecurity PKI as a long-lead migration priority.
 */
