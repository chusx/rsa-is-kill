/*
 * sod_inspection_and_aa.c
 *
 * Border-inspection-system side of ICAO 9303 e-passport verification:
 * SOD signature chain (DS → CSCA) + Active Authentication + EAC
 * Terminal Authentication. Runs on the CBP primary-inspection
 * kiosk, EU EES self-service gate, or airline DCS e-passport
 * verifier.
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include "mrtd.h"
#include "rsa_pkcs1v15.h"
#include "rsa_pss.h"
#include "x509.h"

/* Trust store: ICAO PKD master list — all partner-state CSCAs. */
extern const struct csca_entry {
    char     country[3];
    uint8_t  cert[4096];
    size_t   cert_len;
} ICAO_PKD_CSCA[256];


/* =========================================================
 *  1. SOD (Document Security Object) verification
 * ========================================================= */

struct sod {
    uint8_t  dg_hashes[16][32];      /* DG1..DG16 SHA-256 (when present) */
    uint8_t  dg_present_mask[2];     /* bitmap of DGs covered */
    uint8_t  ds_cert[2048];          /* Document Signer cert */
    size_t   ds_cert_len;
    uint8_t  sig[512];               /* RSA-4096 over dg_hashes block */
    size_t   sig_len;
    char     issuing_country[3];
};

int inspect_read_and_verify_sod(struct sod *s,
                                 const uint8_t dg1[], size_t dg1_len,
                                 const uint8_t dg2[], size_t dg2_len,
                                 const uint8_t dg3[], size_t dg3_len)
{
    /* Locate CSCA for issuing country in PKD trust store. */
    const struct csca_entry *csca = pkd_lookup(s->issuing_country);
    if (!csca) return ERR_UNKNOWN_STATE;

    /* Chain the DS cert to the state's CSCA. */
    if (x509_chain_verify(s->ds_cert, s->ds_cert_len,
                          csca->cert, csca->cert_len) != 0)
        return ERR_DS_CHAIN;

    /* Check DS cert NotAfter — DS certs are short-lived. */
    if (!x509_within_validity(s->ds_cert, s->ds_cert_len,
                               (uint32_t)time(NULL)))
        return ERR_DS_EXPIRED;

    /* Integrity of each present DG against the SOD digest. */
    uint8_t h[32];
    if (s->dg_present_mask[0] & 0x02) {   /* DG1 */
        sha256(dg1, dg1_len, h);
        if (memcmp(h, s->dg_hashes[0], 32)) return ERR_DG1;
    }
    if (s->dg_present_mask[0] & 0x04) {   /* DG2 */
        sha256(dg2, dg2_len, h);
        if (memcmp(h, s->dg_hashes[1], 32)) return ERR_DG2;
    }
    if (s->dg_present_mask[0] & 0x08) {   /* DG3 — EAC-protected */
        sha256(dg3, dg3_len, h);
        if (memcmp(h, s->dg_hashes[2], 32)) return ERR_DG3;
    }

    /* Extract DS pubkey and verify SOD signature. */
    uint8_t n[512], e[4];
    size_t n_len, e_len;
    x509_extract_pub(s->ds_cert, s->ds_cert_len,
                     n, sizeof n, &n_len, e, sizeof e, &e_len);
    sha256(&s->dg_hashes[0][0], sizeof s->dg_hashes, h);
    return rsa_pkcs1v15_verify_sha256(n, n_len, e, e_len,
                                      h, 32, s->sig, s->sig_len);
}


/* =========================================================
 *  2. Active Authentication — chip proves it isn't a clone
 * ========================================================= */

int aa_challenge_chip(const uint8_t dg15[], size_t dg15_len)
{
    uint8_t challenge[8];
    rng_bytes(challenge, sizeof challenge);

    uint8_t chip_sig[256];
    size_t  sig_len;
    if (mrtd_send_internal_auth(challenge, sizeof challenge,
                                 chip_sig, &sig_len) != 0)
        return ERR_AA_TRANSPORT;

    /* DG15 carries the chip's AA public key. */
    uint8_t n[256], e[4];
    size_t n_len, e_len;
    dg15_extract_aa_pub(dg15, dg15_len,
                        n, sizeof n, &n_len, e, sizeof e, &e_len);

    /* ISO 9796-2 DS1 signature scheme used in AA; simplified to
     * PKCS#1 v1.5 verify here. */
    uint8_t h[32];
    sha256(challenge, sizeof challenge, h);
    return rsa_pkcs1v15_verify_sha256(n, n_len, e, e_len,
                                      h, 32, chip_sig, sig_len);
}


/* =========================================================
 *  3. Terminal Authentication (EAC) — our kiosk proving it's
 *  authorised to read fingerprints
 * ========================================================= */

int eac_terminal_auth(void)
{
    /* Present CVCA → DVCA → Terminal chain stored in the kiosk HSM.
     * The chip responds with a challenge; we sign with Terminal
     * private key (RSA-2048 most deployments). */
    uint8_t chain[3072];
    size_t chain_len = kiosk_export_cv_chain(chain, sizeof chain);
    mrtd_mse_set_dst(chain, chain_len);

    uint8_t chip_nonce[16];
    mrtd_get_challenge(chip_nonce, sizeof chip_nonce);

    uint8_t sig[256], h[32];
    sha256(chip_nonce, sizeof chip_nonce, h);
    kiosk_hsm_rsa_sign(TERMINAL_SIGNING_KEY, h, 32, sig, sizeof sig);

    return mrtd_external_authenticate(sig, sizeof sig);
}


/* ---- Breakage ---------------------------------------------
 *
 *  CSCA factored: attacker forges DS certs → any-name-any-nation
 *  e-passports accepted by every ICAO-conformant border kiosk.
 *  Not detectable without PKD CRL push; many kiosks don't do
 *  online status. Criminal + counter-terrorism shield gone for a
 *  decade-plus rotation window.
 *
 *  DS key factored: a ~90-day batch of forged passports for that
 *  issuing run, harder to revoke per-document.
 *
 *  Terminal CVCA factored: unauthorised fingerprint DG3 reads
 *  worldwide against EAC-protected documents.
 */
