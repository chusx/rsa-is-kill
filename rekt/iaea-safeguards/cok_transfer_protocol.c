/*
 * cok_transfer_protocol.c
 *
 * IAEA Department of Safeguards NGSS (Next Generation
 * Surveillance System) "Chain of Knowledge" (CoK) data
 * transfer protocol. Every surveillance artifact — camera
 * frame, seal event, radiation monitor reading, fuel-rod
 * serial inventory — is signed on the in-field NGSS data
 * collector (Aquila, GDATA) and uploaded to the Vienna HQ
 * Safeguards Data Lake. The transfer is over a dedicated
 * IAEA VPN (RSA-IKEv2) or via inspector-carried SDWAN key.
 *
 * The CoK is THE evidentiary chain that distinguishes
 * "this fuel rod is accounted for" from "material has been
 * diverted" in an SGA (Safeguards Agreement) inspection.
 * Tampering with the CoK is a state-level diversion act
 * under the NPT.
 */

#include <stdint.h>
#include <string.h>
#include "ngss.h"

extern const uint8_t IAEA_NGSS_ROOT_PUB[384];     /* RSA-3072   */
extern const uint8_t STATE_SRA_ROOT_PUB[384];      /* state SRA  */

enum cok_artifact_type {
    COK_CAMERA_FRAME        = 0x01,
    COK_SEAL_EVENT          = 0x02,    /* E-seal open/close      */
    COK_RADIATION_SPECTRUM  = 0x03,    /* IRAT / FDET / ICVD     */
    COK_ITEM_INVENTORY      = 0x04,    /* fuel-rod / UF6 cyl     */
    COK_CONTAINMENT_VERIFY  = 0x05,    /* laser seal / 3D scan   */
};

struct cok_record {
    char       facility_code[8];       /* e.g. "IRRN-010"        */
    char       mba_zone[8];            /* material balance area   */
    uint8_t    artifact_type;
    uint32_t   seq;
    uint64_t   ts_utc_ns;
    uint8_t    data_sha256[32];        /* hash of payload file    */
    uint32_t   data_len;
    /* Signed by the NGSS data collector's device cert, which
     * chains to IAEA_NGSS_ROOT. Inspector physically unseals
     * the collector to download. */
    uint8_t    collector_cert[2048]; size_t collector_cert_len;
    uint8_t    sig[384];
};

int cok_validate_record(const struct cok_record *r)
{
    if (r->seq <= cok_last_seq(r->facility_code, r->mba_zone))
        return COK_REPLAY;

    if (x509_chain_verify(r->collector_cert, r->collector_cert_len,
            IAEA_NGSS_ROOT_PUB, sizeof IAEA_NGSS_ROOT_PUB))
        return COK_CHAIN;

    uint8_t h[32];
    sha256_of(r, offsetof(struct cok_record, collector_cert), h);
    if (verify_with_cert(r->collector_cert, r->collector_cert_len,
                         h, r->sig, sizeof r->sig))
        return COK_SIG;

    cok_seq_bump(r->facility_code, r->mba_zone, r->seq);
    return COK_ACCEPT;
}

/* =========================================================
 *  E-seal challenge-response (IAEA V-CAM / E-Seal):
 *  the inspector's handheld (IAEA "PANDA") queries the
 *  seal; the seal signs its tamper-log with a device cert
 *  chained to IAEA_NGSS_ROOT.
 * ========================================================= */
struct eseal_status {
    char       seal_serial[16];
    uint8_t    tamper_state;           /* 0 = ok, !0 = breach    */
    uint64_t   last_event_ts;
    uint16_t   battery_pct;
    uint8_t    device_cert[512]; size_t device_cert_len;
    uint8_t    sig[384];
};

/* =========================================================
 *  DIV report builder: the Safeguards inspector uses this
 *  to sign a Design Information Verification report from
 *  the field. If this signature is forgeable, a state actor
 *  can submit falsified DIV records for a facility and
 *  prevent the IAEA from triggering an SIT / SIR (special
 *  inspection request).
 * ========================================================= */
struct div_report {
    char       facility_code[8];
    char       inspector_id[16];
    uint32_t   report_seq;
    uint64_t   visit_start_ns;
    uint64_t   visit_end_ns;
    uint8_t    findings_sha256[32];    /* hash of PDF report     */
    /* Inspector signs with their personal cert issued by IAEA
     * PKI. Cert carries a "safeguards role" extension. */
    uint8_t    inspector_cert[2048]; size_t inspector_cert_len;
    uint8_t    inspector_sig[384];
    /* State SRA (state regulatory authority) co-signs per SGA. */
    uint8_t    sra_cert[2048]; size_t sra_cert_len;
    uint8_t    sra_sig[384];
};

/* ---- Proliferation consequence ---------------------------
 *  IAEA_NGSS_ROOT factored:
 *    - Forge CoK records: make it appear a fuel rod is still
 *      in the spent-fuel pool when it has been removed.
 *      Masks ~8 kg Pu diversion (1 SQ, INFCIRC/153 def).
 *    - Forge E-seal attestations: IAEA believes containment
 *      was intact between inspections.
 *    - Forge DIV reports: facility modifications go unreported.
 *    A proliferant state with the factored key can defeat the
 *    safeguards regime for years. Discovery at next physical
 *    inspection (annual cycle for light-water reactor; shorter
 *    for enrichment plants under AP).
 *  STATE_SRA_ROOT factored:
 *    External actor forges the state's co-signature on DIV
 *    reports, injecting conflicting records to trigger a
 *    special-inspection demand against a compliant state —
 *    geopolitical weapon disguised as non-compliance evidence.
 *  Recovery: IAEA replaces NGSS trust anchors + every field
 *  device globally (~20k devices across 1200 facilities in
 *  ~180 states). Multi-year logistic program; interim is
 *  inspector-physical-presence-only verification.
 * --------------------------------------------------------- */
