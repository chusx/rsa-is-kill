/*
 * reagent_rfid_and_run_start.c
 *
 * Illumina NovaSeq X / NextSeq 2000 reagent cartridge ingest +
 * sequencing-run start. Runs on the instrument control PC (Windows-
 * embedded + C++/C#) as part of the SBS run-control service.
 *
 * Every run begins with:
 *   1. Operator scans or loads reagent cartridges into the bay.
 *   2. Instrument reads RFID, RSA-verifies the factory-issued
 *      lot-credential signature.
 *   3. Instrument queries BaseSpace for recall / expiration check
 *      over TLS mutual-auth.
 *   4. Run-control firmware self-verifies its own signed build
 *      image against the Illumina code-signing root.
 *   5. On all-OK, sequencing proceeds; otherwise the run is
 *      locked and the operator sees an error code (e.g. ER1234
 *      "reagent authentication failed").
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include "illumina_run.h"
#include "rsa_pss.h"
#include "sha256.h"

/* ---- Trust anchors (factory-programmed into TPM2 at manufacture) */
extern const uint8_t ILLUMINA_REAGENT_ROOT_PUB[384];     /* RSA-3072 */
extern const uint8_t ILLUMINA_FW_SIGN_ROOT_PUB[384];     /* RSA-3072 */
extern const uint8_t ILLUMINA_BASESPACE_CA_PUB[384];     /* RSA-3072 */
extern const uint8_t INSTRUMENT_PRIV_HANDLE;             /* TPM2 slot */


/* ---- Reagent cartridge RFID payload ---------------------- */
struct reagent_credential {
    char      kit_sku[16];            /* e.g. "20067770" NovaSeq X 25B */
    char      lot_id[12];             /* unique lot */
    uint32_t  mfg_ts;
    uint32_t  expiry_ts;              /* unix seconds; kit refuses after */
    uint8_t   chemistry_version;
    uint8_t   reagent_type;           /* 1=Cluster, 2=SBS, 3=Buffer */
    uint8_t   reserved[6];
    uint8_t   sig[384];               /* RSA-3072 PSS-SHA256 */
};

static int verify_reagent_credential(const struct reagent_credential *c)
{
    /* Compute hash over the struct minus the signature. */
    uint8_t h[32];
    sha256_of(c, offsetof(struct reagent_credential, sig), h);

    /* Fixed e=65537 on Illumina's reagent root */
    return rsa_pss_verify_sha256(
        ILLUMINA_REAGENT_ROOT_PUB, sizeof ILLUMINA_REAGENT_ROOT_PUB,
        (uint8_t[]){0x01,0x00,0x01}, 3,
        h, sizeof h,
        c->sig, sizeof c->sig);
}


/* ---- 1. Cartridge ingest ------------------------------------ */

int ingest_cartridge(int bay_idx)
{
    struct reagent_credential cred;
    if (rfid_read_credential(bay_idx, &cred, sizeof cred) != 0)
        return ERR_RFID_READ;

    if (verify_reagent_credential(&cred) != 0) {
        log_event("ER1234 reagent auth FAILED bay=%d lot=%s",
                  bay_idx, cred.lot_id);
        return ERR_REAGENT_AUTH;
    }

    if ((uint32_t)time(NULL) > cred.expiry_ts) {
        log_event("ER1237 reagent EXPIRED bay=%d lot=%s", bay_idx, cred.lot_id);
        return ERR_REAGENT_EXPIRED;
    }

    /* BaseSpace recall-check (TLS mutual auth) */
    if (basespace_reagent_recall_check(cred.lot_id) != 0) {
        log_event("ER1240 reagent RECALLED lot=%s", cred.lot_id);
        return ERR_REAGENT_RECALLED;
    }

    save_bay_metadata(bay_idx, &cred);
    return OK;
}


/* ---- 2. Firmware self-verify ------------------------------ */

struct fw_manifest {
    char      product[16];
    char      build_version[32];
    uint8_t   rom_image_sha256[32];
    uint8_t   fpga_bitstream_sha256[32];
    uint8_t   windows_image_sha256[32];
    uint8_t   sig[384];
};

int fw_self_verify(void)
{
    struct fw_manifest *m = read_manifest_from_partition();

    uint8_t measured[32];
    sha256_partition(PART_CONTROL_SW, measured);
    if (memcmp(measured, m->rom_image_sha256, 32)) return -1;
    sha256_partition(PART_FPGA_BITSTREAM, measured);
    if (memcmp(measured, m->fpga_bitstream_sha256, 32)) return -1;

    uint8_t h[32];
    sha256_of(m, offsetof(struct fw_manifest, sig), h);
    return rsa_pss_verify_sha256(
        ILLUMINA_FW_SIGN_ROOT_PUB, sizeof ILLUMINA_FW_SIGN_ROOT_PUB,
        (uint8_t[]){0x01,0x00,0x01}, 3,
        h, 32, m->sig, sizeof m->sig);
}


/* ---- 3. Run start orchestration --------------------------- */

int begin_sequencing_run(const char *run_name, uint32_t cycles_r1,
                          uint32_t cycles_r2, uint32_t index1, uint32_t index2)
{
    if (fw_self_verify() != 0) {
        log_event("ER0001 firmware self-verify FAILED; refusing run");
        return ERR_FW_INTEGRITY;
    }

    for (int b = 0; b < NUM_REAGENT_BAYS; b++) {
        if (bay_occupied(b) && bay_validated(b) != OK)
            return ERR_BAY_INVALID;
    }

    /* Open a TLS mutual-auth session to BaseSpace; client cert is
     * the instrument's per-serial RSA-2048 leaf, issued by the
     * Illumina factory CA. */
    bs_session_t *bs = basespace_connect_mutual_tls(
            INSTRUMENT_PRIV_HANDLE,
            "/factory/certs/instrument-leaf.crt",
            ILLUMINA_BASESPACE_CA_PUB, sizeof ILLUMINA_BASESPACE_CA_PUB);
    if (!bs) return ERR_BASESPACE_CONN;

    basespace_announce_run_start(bs, run_name, cycles_r1, cycles_r2,
                                  index1, index2);

    run_sbs_cycles(cycles_r1, cycles_r2);

    /* At run completion, sign the RunInfo + InterOp metrics with
     * the instrument's own RSA key before upload. This signature
     * is what CAP/CLIA-accredited clinical laboratories retain as
     * the chain-of-custody evidence for each run. */
    sign_run_info_and_upload(bs, run_name, INSTRUMENT_PRIV_HANDLE);
    basespace_close(bs);
    return OK;
}


/* ---- Breakage -----------------------------------------------
 *
 *   Factor the Illumina reagent-signing RSA-3072 root:
 *     - Gray-market reagent suppliers sign counterfeit-lot RFID
 *       credentials; clinical labs unknowingly run assays on
 *       chemistry that wasn't QC-validated. Downstream:
 *       unreliable variant calls in germline + tumor NGS tests,
 *       with patient-care consequences.
 *
 *   Factor the firmware-signing root:
 *     - Attacker distributes a signed control-software update
 *       that tampers with base-calling or filters clinically-
 *       relevant variants from VCF output. Fleet-wide silent
 *       corruption of sequencing data across clinical labs.
 *
 *   Factor the BaseSpace client-CA:
 *     - Forge per-instrument telemetry; fabricate run-start /
 *       run-completion records. Integrity of the audit trail for
 *       FDA/ISO 15189-accredited clinical NGS is compromised.
 *
 *   Factor an instrument's per-serial cert (post-leak or side
 *   channel, combined with a factoring attack):
 *     - Attacker spoofs a specific hospital's NovaSeq X
 *       identity in BaseSpace, uploads fabricated run records
 *       tied to real clinical-lab accession numbers. Forensic-
 *       casework use of NGS (rape kits, disaster victim ID,
 *       paternity) has evidence-integrity consequences.
 */
