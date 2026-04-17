/*
 * border_inspection_system.c
 *
 * Inspection System (IS) side of the ICAO 9303 ePassport read cycle as
 * it actually runs at a border control booth / e-gate.  Orchestrates
 * Basic/PACE access control, Chip Authentication, and Passive
 * Authentication on top of the RSA primitives in
 * `icao_9303_passive_auth.c`.
 *
 * Deployed in: every e-gate vendor (Vision-Box, IDEMIA MorphoWay,
 * Gemalto/Thales Border Gateway, SITA Smart Path, Gunnebo ImmSec)
 * and desk-side inspection kiosks at IATA airports worldwide.
 * Sovereign operators: DHS CBP (USA), UKVI/Border Force, Frontex
 * Eurosur, Australian Border Force, Hong Kong ImmD, Japan NIJ.
 */

#include <stdint.h>
#include "icao_9303.h"
#include "icao_csca_masterlist.h"


struct ePassport {
    /* MRZ-derived BAC/PACE seed */
    char     mrz[44*2];

    /* LDS (Logical Data Structure) data groups */
    uint8_t  ef_com[256];     size_t ef_com_len;
    uint8_t  ef_sod[8192];    size_t ef_sod_len;   /* Document Security Object, RSA-signed by DS cert */
    uint8_t  dg1[128];  size_t dg1_len;            /* MRZ                */
    uint8_t  dg2[32768]; size_t dg2_len;           /* Face biometric JP2 */
    uint8_t  dg3[32768]; size_t dg3_len;           /* Fingerprints — EAC */
    uint8_t  dg14[512]; size_t dg14_len;           /* CA / ChipAuth keys */
    uint8_t  dg15[512]; size_t dg15_len;           /* AA public key     */

    /* Document Signer cert carried in EF.SOD, chained to issuing-state CSCA */
    uint8_t  ds_cert_der[2048]; size_t ds_cert_len;
    uint8_t  issuing_state[3];                     /* e.g. "DEU" */
};


int
border_read_epassport(struct ePassport *p, struct is_session *is)
{
    /* 1.  PACE if chip supports it; BAC otherwise.  Access-control
     *     seed comes from the MRZ OCR scan. */
    if (icao_try_pace(is, p->mrz) != 0) {
        if (icao_run_bac(is, p->mrz) != 0) return IS_DENY_READ;
    }

    /* 2.  Read LDS data groups.  DG3 (fingerprints) requires Terminal
     *     Authentication (EAC) with the state's Terminal CVCA chain —
     *     Schengen SPOC network distributes the certs. */
    icao_read_ef(is, 0x011E, p->ef_com, &p->ef_com_len);
    icao_read_ef(is, 0x011D, p->ef_sod, &p->ef_sod_len);
    icao_read_ef(is, 0x0101, p->dg1,    &p->dg1_len);
    icao_read_ef(is, 0x0102, p->dg2,    &p->dg2_len);
    icao_read_ef(is, 0x010E, p->dg14,   &p->dg14_len);
    icao_read_ef(is, 0x010F, p->dg15,   &p->dg15_len);
    if (icao_run_terminal_auth(is, p->issuing_state) == 0)
        icao_read_ef(is, 0x0103, p->dg3, &p->dg3_len);

    /* 3.  Passive Authentication.  The heart of chip-integrity
     *     verification and the step that dies under a factoring
     *     attack:
     *       a. Parse SOD → recover DS cert + CMS SignerInfo.
     *       b. Walk DS → CSCA (issuing-state root) via the ICAO PKD
     *          Master List that this IS syncs hourly.
     *       c. Verify RSA-SHA256 signature over hashes of DG1..DG16.
     *       d. Re-hash each DG read from chip and match. */
    if (icao_passive_authenticate(p) != 0)
        return IS_DENY_AUTHENTICITY;

    /* 4.  Active Authentication (DG15): chip signs IS challenge with
     *     its on-card RSA private key — proves the chip itself isn't
     *     a clone, only the LDS. Chip Authentication (DG14) performs
     *     a similar anti-clone check over ECDH. */
    if (p->dg15_len && icao_active_authenticate(is, p) != 0)
        return IS_DENY_CLONE_SUSPECTED;

    /* 5.  Cross-check MRZ OCR against DG1, face template against
     *     DG2 via the SDK (Neurotechnology / Idemia / Aware).  Push
     *     match result and IS decision into APIS / E-Borders. */
    border_biometric_match(p, is);
    return IS_ALLOW;
}


/* Failure modes under a factoring attack on a CSCA (Country Signing
 * Certification Authority):
 *   - Attackers mint Document Signer certs that chain to a
 *     legitimate CSCA and forge EF.SOD over arbitrary LDS data,
 *     producing e-gate-passable passports under any identity for
 *     that country.
 *   - Active Authentication doesn't help on its own because the IS
 *     already trusts DG15 contents via SOD → DS → CSCA.
 *   - Countries whose CSCA is RSA (most: Germany, France, UK,
 *     Netherlands, India, Brazil, Japan — ICAO PKD shows the
 *     RSA-vs-ECDSA split) lose e-Border integrity at the first
 *     factoring. Countries on ECDSA CSCAs (growing minority since
 *     late-2010s) survive the attack. */
