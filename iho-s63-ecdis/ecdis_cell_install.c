/*
 * ecdis_cell_install.c
 *
 * IHO S-63 v1.2 / v2.0 ENC (Electronic Navigational Chart) cell
 * installer on board an ECDIS (Electronic Chart Display and
 * Information System).  Drives the S-63 permit check + chart-data
 * integrity verification whose RSA primitives are in
 * `s63_permit_verify.c`.
 *
 * Every SOLAS-regulated ship (commercial cargo > 500 GT, passenger
 * ships, tankers — tens of thousands of hulls worldwide) is required
 * by IMO SOLAS Chapter V Regulation 19 to carry ECDIS in paperless
 * voyage. Deployed ECDIS: Furuno FMD-3x00, JRC JAN-9201, SAM
 * ElectronicS NACOS, Raytheon Anschütz SynapsisNX, Kongsberg K-Chart
 * EC-1. All of them route chart installation through this path.
 *
 * IHO S-63 distributes data under a two-tier PKI:
 *   - SA (Scheme Administrator) root — IHO operates it, RSA-1024/2048
 *   - Data Server cert per RENC (Regional ENC Coordinator): PRIMAR,
 *     IC-ENC, plus hydrographic offices (UKHO, NOAA, DHN Brazil, JHA
 *     Japan, Russian GUNiO, NGA US mil for classified overlays)
 */

#include <stdint.h>
#include <string.h>
#include "s63.h"
#include "iho_sa_root.h"


struct ecdis_permit_db {
    char    user_permit[28];      /* hardware-bound HW_ID + M_ID */
    char    encrypted_cell_perms[16384];
    uint8_t sa_sig_der[1024];
    size_t  sa_sig_len;
};


int
ecdis_install_exchange_set(struct ecdis_permit_db *db,
                            const char *exchange_set_root)
{
    /* 1.  Verify PERMIT.TXT — each line is HW_ID-bound, cell-scoped,
     *     contains a subscription expiry date, and the whole file is
     *     signed by the issuing Data Server under their RSA-2048 key.
     *     Data Server cert chains to the IHO SA root. */
    if (s63_verify_permit_signature(db, iho_sa_root_der) != 0)
        return ECDIS_PERMIT_INVALID;

    /* 2.  For each cell in the exchange set:
     *       a. Read CATALOG.031 manifest
     *       b. Check digital signature on manifest
     *       c. For each .000 / .NNN base / update cell:
     *            - hash matches SIGNATURE file
     *            - RSA-sig in SIGNATURE file verifies under Data
     *              Server cert (same RSA key used for PERMIT) */
    struct catalog_031 cat;
    if (s63_read_catalog_031(exchange_set_root, &cat) != 0)
        return ECDIS_PERMIT_INVALID;
    if (s63_verify_catalog_rsa(&cat, iho_sa_root_der) != 0)
        return ECDIS_PERMIT_INVALID;

    for (size_t i = 0; i < cat.n_cells; i++) {
        if (s63_verify_cell_rsa_sig(&cat.cells[i], iho_sa_root_der) != 0)
            return ECDIS_CELL_CORRUPT;

        /* 3. Cell-key decryption: PERMIT line yields two per-cell
         *    CK1/CK2 keys (Blowfish) wrapped under the HW_ID. Once
         *    unwrapped, the cell's .000 blob is decrypted and
         *    imported into the ECDIS SENC (System-ENC) store for
         *    rendering. */
        s63_decrypt_cell_to_senc(&cat.cells[i], db);
    }

    /* 4.  Update the ECDIS SENC index, push "Charts Updated"
     *     notice to the OOW (Officer of the Watch) display, and
     *     append to the passage-plan evidentiary log (required by
     *     IMO Res. A.893(21)). */
    senc_reindex();
    voyage_log_chart_update(cat.n_cells);
    return 0;
}


/* Breakage:
 *
 * IHO S-63 is the authenticity layer for maritime charting. A
 * factoring attack on the IHO SA root lets an attacker:
 *   - Forge Data Server certs and distribute chart updates that
 *     ECDIS installs without warning
 *   - Insert falsified cells for specific navigational hazards —
 *     shifted buoy positions, erased reef markings, forged
 *     depth contours — targeted at a specific ship's route
 * This has obvious national-security salience (GPS spoofing is already
 * a documented asymmetric-warfare tool in the Persian Gulf and Black
 * Sea; chart-spoofing is a strictly stronger primitive because ECDIS
 * operators train to trust charts over GPS when they disagree).
 * UKHO/NOAA have been planning ECDSA migration in the S-100 framework
 * for exactly this reason.
 */
