/*
 * vu_download_workflow.c
 *
 * EU digital tachograph Vehicle Unit (VU) ↔ workshop-card / control-card
 * authenticated download session. Mandated by Commission Regulation
 * (EU) 2016/799 "smart tachograph" and its Gen 2 v2 amendment
 * (2021/1228). Every HGV and coach in the EU carries a VU; every fleet
 * workshop, enforcement officer, and company card holder goes through
 * this session to legally read driver activity data.
 *
 * The RSA primitives (card-to-VU mutual authentication, session-key
 * derivation, MAC-over-signature) live in `tacho_rsa_card.c`; this
 * file is the ISO 16844-3 / Annex 1C download protocol orchestration.
 *
 * Deployed in VUs from Stoneridge, Continental VDO (now Vitesco), Intellic,
 * and Actia. Cards issued by ~27 Member State Authorities (UK Driver &
 * Vehicle Standards Agency, German KBA, French Chronoservices, etc.)
 * and chained to the ERCA (European Root Certification Authority at
 * the JRC in Ispra). ERCA's root is RSA-2048 Gen1 / RSA-3072 Gen2v2.
 */

#include <stdint.h>
#include <string.h>
#include "tacho_card.h"    /* APDU + RSA primitives */

enum vu_download_step {
    STEP_SELECT_TACHO_AID   = 0,
    STEP_GET_CHALLENGE      = 1,
    STEP_MUTUAL_AUTH_RSA    = 2,
    STEP_READ_OVERVIEW      = 3,
    STEP_READ_ACTIVITIES    = 4,
    STEP_READ_EVENTS_FAULTS = 5,
    STEP_READ_DETAILED_SPEED= 6,
    STEP_READ_TECHNICAL     = 7,
    STEP_READ_CARD_DLOAD    = 8,
    STEP_SIGNOFF            = 9,
};


/* Workshop-card-driven download (calibration / repair).  Control cards
 * run the same flow but with different read permissions enforced
 * server-side inside the VU. */
int
vu_perform_download(struct tacho_card *card,       /* PC/SC handle */
                     struct vu_session *vu,
                     uint8_t *out_blob,            /* C1B container */
                     size_t  out_cap,
                     size_t *out_len)
{
    int rc;

    /* 1.  SELECT Tachograph AID on the card + read card certs +
     *     ERCA trust chain.  The VU independently resolves the chain
     *     against its on-board ERCA anchor list (updated via
     *     workshop-card push during calibration). */
    rc = card_select_tacho(card);                            if (rc) return rc;
    rc = card_read_ca_cert_rsa(card);                        if (rc) return rc;
    rc = card_read_card_cert_rsa(card);                      if (rc) return rc;
    rc = vu_verify_card_chain_rsa(vu, card);                 if (rc) return rc;

    /* 2.  Card ↔ VU mutual auth via RSA challenge/response.  This is
     *     the step that collapses under a factoring attack: the VU
     *     nonce is signed by the card's RSA private key, and vice
     *     versa.  Success yields a pair of 3DES (Gen1) or AES-128
     *     (Gen2) session keys K_MAC + K_ENC. */
    rc = tacho_mutual_auth_rsa(card, vu);                    if (rc) return rc;

    /* 3.  Pull the full Annex 1C data-transfer sequence.  Each
     *     record has its own digital-signature structure appended —
     *     signed by the VU's motion-sensor-pairing RSA key — so that
     *     downstream analysis tools (TachoSafe, Tacho2Safe, Stoneridge
     *     OPTAC) can revalidate evidentiary integrity even offline. */
    rc = vu_read_tre("Overview",          out_blob, out_cap, out_len); if (rc) return rc;
    rc = vu_read_tre("Activities",        out_blob, out_cap, out_len); if (rc) return rc;
    rc = vu_read_tre("EventsFaults",      out_blob, out_cap, out_len); if (rc) return rc;
    rc = vu_read_tre("DetailedSpeed",     out_blob, out_cap, out_len); if (rc) return rc;
    rc = vu_read_tre("Technical",         out_blob, out_cap, out_len); if (rc) return rc;
    rc = vu_read_tre("CardDownload",      out_blob, out_cap, out_len); if (rc) return rc;

    /* 4.  End-of-session: VU emits a signature over the full blob
     *     using its motion-sensor-pairing RSA key so enforcement
     *     officers (Gendarmerie, Vlaamse Politie, Guardia Civil,
     *     DVSA) can later prove tamper-evidence in court. */
    rc = vu_emit_signature_rsa(vu, out_blob, *out_len);      if (rc) return rc;

    return 0;
}


/* Reality check: a factoring attack on the ERCA hierarchy lets an
 * attacker mint cards that a VU will treat as legitimate workshop or
 * enforcement cards (bypassing drive-time limits during calibration),
 * and lets a mechanic's laptop forge VU signatures on downloaded blobs
 * — completely invalidating the evidentiary value of tachograph data
 * across the EU's road-freight industry. EU tachograph fraud is already
 * a ~€1-3B/year criminal economy under pre-Gen2 keys; an RSA break is
 * an upgrade from "expensive to forge" to "free." */
