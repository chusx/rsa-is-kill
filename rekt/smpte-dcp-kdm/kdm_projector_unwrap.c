/*
 * kdm_projector_unwrap.c
 *
 * Digital-cinema Integrated Media Block (IMB) / Security Manager
 * side of SMPTE ST 430-1 KDM ingest + ST 429-9 DCP playback.
 * Pattern matches Dolby IMS3000, Christie IMB-S3, Barco ICMP,
 * GDC SR-1000, Qube Xi/Pro.
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include "imb.h"
#include "rsa_oaep.h"
#include "rsa_pss.h"
#include "aes.h"

extern const uint8_t DISTRIBUTOR_TRUST_BUNDLE_PEM[];
extern const uint8_t VENDOR_SM_ROOT_PUB[512];


/* =========================================================
 *  1. KDM ingest — XML parsed to this struct
 * ========================================================= */

struct kdm {
    char      cpl_id[64];                /* references a Composition Playlist */
    uint32_t  content_key_not_before;
    uint32_t  content_key_not_after;
    uint8_t   recipient_sm_fingerprint[32];   /* SHA-256 of our SM cert */
    uint32_t  n_key_blobs;
    struct {
        char     key_id[40];             /* UUID of an AES key */
        uint8_t  enc_blob[256];          /* RSA-OAEP-wrapped AES key + metadata */
        size_t   enc_len;
    } keys[32];
    uint8_t   signer_cert[2048];
    size_t    signer_cert_len;
    uint8_t   xmldsig[384];
    size_t    sig_len;
};


int imb_ingest_kdm(const struct kdm *k)
{
    /* 1. Recipient binding — KDM must target THIS projector. */
    uint8_t our_fp[32];
    sm_cert_fingerprint(our_fp);
    if (memcmp(our_fp, k->recipient_sm_fingerprint, 32))
        return ERR_WRONG_RECIPIENT;

    /* 2. Signer cert must chain to an authorised studio trust
     *    anchor in our bundled DISTRIBUTOR_TRUST_BUNDLE_PEM. */
    if (distributor_chain_verify(k->signer_cert, k->signer_cert_len) != 0)
        return ERR_DIST_CHAIN;

    /* 3. XMLDSig signature over the KDM body. Production IMBs use
     *    a proper XMLDSig verifier; simplified here to a raw hash
     *    over canonicalised fields. */
    uint8_t n[384], e[4];
    size_t n_len, e_len;
    x509_extract_pub(k->signer_cert, k->signer_cert_len,
                     n, sizeof n, &n_len, e, sizeof e, &e_len);

    uint8_t h[32];
    kdm_c14n_digest(k, h);
    if (rsa_pss_verify_sha256(n, n_len, e, e_len,
                              h, 32, k->xmldsig, k->sig_len) != 0)
        return ERR_KDM_SIG;

    /* 4. Window check — IMB real-time clock (tamper-responding,
     *    loss of power = time auth loss = security alert). */
    uint32_t now = sm_trusted_clock();
    if (now < k->content_key_not_before ||
        now > k->content_key_not_after)
        return ERR_KDM_WINDOW;

    /* 5. Per-reel AES keys: unwrap with SM's RSA-2048 private key
     *    (inside tamper-responding enclosure). */
    for (uint32_t i = 0; i < k->n_key_blobs; i++) {
        uint8_t aes_and_meta[128];
        size_t  out_len = sizeof aes_and_meta;
        if (rsa_oaep_decrypt_sha256_se(
                SM_PRIVATE_KEY,
                k->keys[i].enc_blob, k->keys[i].enc_len,
                aes_and_meta, &out_len) != 0 || out_len < 16)
            return ERR_UNWRAP;

        /* First 16 bytes = AES-128 key; remainder = structured
         * metadata (cipher type, integrity nonce, usage flags). */
        sm_install_content_key(
            k->keys[i].key_id,
            aes_and_meta, 16,
            aes_and_meta + 16, out_len - 16,
            k->content_key_not_before,
            k->content_key_not_after);
        secure_wipe(aes_and_meta, sizeof aes_and_meta);
    }

    audit_log("KDM-OK cpl=%s keys=%u window=[%u,%u]",
              k->cpl_id, k->n_key_blobs,
              k->content_key_not_before,
              k->content_key_not_after);
    return 0;
}


/* =========================================================
 *  2. Playback gate — called by the decoder per-reel
 * ========================================================= */

int sm_authorise_reel_playback(const char *cpl_id, const char *reel_key_id,
                               uint8_t *key_out, size_t key_out_len)
{
    if (!cpl_loaded_and_signature_valid(cpl_id)) return ERR_CPL_SIG;
    if (!projector_on_tdl_for_cpl(cpl_id))       return ERR_TDL_REVOKED;

    uint32_t now = sm_trusted_clock();
    return sm_release_content_key_if_in_window(
        reel_key_id, now, key_out, key_out_len);
}


/* =========================================================
 *  3. Composition Playlist + Packing List signature verify
 * ========================================================= */

int verify_cpl_and_pkl(const uint8_t *cpl_xml, size_t cpl_len,
                      const uint8_t *pkl_xml, size_t pkl_len)
{
    /* CPL + PKL both XMLDSig-signed by the originating facility
     * (a lab or the studio). IMB verifies before accepting the
     * composition for playback. */
    if (xmldsig_verify_enveloped_against_trust_bundle(
            cpl_xml, cpl_len,
            DISTRIBUTOR_TRUST_BUNDLE_PEM) != 0)
        return ERR_CPL_SIG;
    if (xmldsig_verify_enveloped_against_trust_bundle(
            pkl_xml, pkl_len,
            DISTRIBUTOR_TRUST_BUNDLE_PEM) != 0)
        return ERR_PKL_SIG;
    return 0;
}


/* ---- Breakage ---------------------------------------------
 *
 *  Vendor SM-root factored (Christie/Barco/NEC/Dolby/GDC):
 *    - Attacker mints a forged-projector cert, receives KDMs
 *      targeted to it, extracts every film's AES content keys.
 *      Clean-source piracy of every theatrical release on day 0.
 *
 *  Distributor DKDM-signing root factored:
 *    - Rogue KDMs issued to any real projector worldwide; any
 *      licensed title playable at any venue at any time.
 *
 *  Studio content-signing key factored:
 *    - Signed CPL/PKL forgeries; the projector accepts an
 *      attacker-substituted composition (propaganda, alternate
 *      audio tracks, malicious test-pattern payloads).
 */
