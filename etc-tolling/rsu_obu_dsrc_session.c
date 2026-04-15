/*
 * rsu_obu_dsrc_session.c
 *
 * CEN-DSRC (5.8 GHz) Roadside Unit ↔ On-Board Unit exchange, the
 * cryptographic core of European free-flow tolling and of Japan's
 * ETC 2.0. The RSU challenges the OBU; OBU proves possession of an
 * RSA-2048 private key tied to a CSC-signed cert. A valid response
 * debits the customer's prepaid balance or generates a settlement
 * claim against the issuing toll agency (EETS roaming).
 *
 * Implementation concept for Kapsch TRP-4010, TransCore eGo 2.0,
 * Q-Free Gemini OBUs; Kapsch JANUS, Mitsubishi Heavy Industries
 * 5.8-GHz ETC 2.0 gantries.
 */

#include <stdint.h>
#include <string.h>
#include "dsrc.h"
#include "rsa_pkcs1_pss.h"
#include "x509.h"

/* Anchored at manufacture: each transponder holds its private key
 * inside a tamper-evident MCU slot + the concession's pubkey. */

struct obu_state {
    uint32_t   obu_id;
    uint8_t    cert_der[1024];       /* RSA-2048 leaf, CSC-signed */
    size_t     cert_len;
    uint32_t   priv_handle;          /* MCU key slot */
    uint32_t   balance_cents;        /* prepaid in non-CO models */
};

struct rsu_state {
    uint8_t    csc_root_pub[384];    /* RSA-3072 concession root */
    uint32_t   gantry_id;
    uint16_t   toll_cents;           /* computed per axle-class */
};


/* ---- 1. Beacon phase: RSU broadcasts BST (Beacon Service Table) */

struct bst {
    uint16_t   bst_type;         /* DSRC_BST_TOLLING_APPLICATION */
    uint32_t   time_stamp;
    uint32_t   gantry_id;
    uint8_t    challenge[32];    /* fresh nonce per vehicle pass */
};


/* ---- 2. OBU VST (Vehicle Service Table) + signed challenge ---- */

struct vst_signed {
    uint32_t   obu_id;
    uint32_t   vehicle_class;    /* Axle class drives toll rate */
    uint8_t    challenge[32];    /* echo RSU nonce */
    uint32_t   time_stamp;
    uint8_t    reserved[4];
};

int obu_build_response(struct obu_state *o,
                        const struct bst *bst,
                        /* out */ uint8_t *frame, size_t *len)
{
    struct vst_signed v = {0};
    v.obu_id = o->obu_id;
    v.vehicle_class = OBU_AXLE_CLASS_2;
    memcpy(v.challenge, bst->challenge, 32);
    v.time_stamp = bst->time_stamp;

    uint8_t hash[32];
    sha256_of(&v, sizeof v, hash);

    uint8_t sig[256];       /* RSA-2048 signature */
    if (rsa_pss_sign_sha256_hsm(
            o->priv_handle,
            hash, sizeof hash,
            sig, sizeof sig) != 0)
        return -1;

    /* Frame: VST || cert || signature. On the DSRC link ~1 ms
     * transaction window at 80 km/h passage speed. */
    size_t off = 0;
    memcpy(frame + off, &v, sizeof v);        off += sizeof v;
    frame[off++] = (o->cert_len >> 8) & 0xff;
    frame[off++] = o->cert_len & 0xff;
    memcpy(frame + off, o->cert_der, o->cert_len); off += o->cert_len;
    memcpy(frame + off, sig, sizeof sig);     off += sizeof sig;
    *len = off;
    return 0;
}


/* ---- 3. RSU verifies signed VST, debits, logs settlement --- */

int rsu_verify_and_debit(struct rsu_state *rsu,
                          const struct bst *bst,
                          const uint8_t *frame, size_t len)
{
    const struct vst_signed *v = (const void *)frame;
    size_t off = sizeof *v;

    /* OBU cert extraction */
    uint16_t cert_len = (frame[off] << 8) | frame[off+1]; off += 2;
    const uint8_t *cert = frame + off;                    off += cert_len;
    const uint8_t *sig  = frame + off;

    /* Chain verify OBU cert → CSC root */
    uint8_t obu_pub_n[256]; size_t n_len;
    uint8_t obu_pub_e[4];   size_t e_len;
    if (x509_verify_and_extract_pub(
            cert, cert_len,
            rsu->csc_root_pub, sizeof rsu->csc_root_pub,
            obu_pub_n, sizeof obu_pub_n, &n_len,
            obu_pub_e, sizeof obu_pub_e, &e_len) != 0)
        return -1;

    /* Nonce-freshness check (defeats replays of previous passes) */
    if (memcmp(v->challenge, bst->challenge, 32) != 0) return -1;
    if (abs_delta(v->time_stamp, bst->time_stamp) > 2) return -1;

    /* Signature verify */
    uint8_t hash[32];
    sha256_of(v, sizeof *v, hash);
    if (rsa_pss_verify_sha256(
            obu_pub_n, n_len, obu_pub_e, e_len,
            hash, sizeof hash, sig, 256) != 0)
        return -1;

    /* Record settlement event: appended to signed gantry log,
     * batch-uploaded hourly to the concession back-office
     * (Autostrade, SANEF, DARS, Telepass Europe, IAG Hub).
     * Inter-agency reconciliation (EETS) re-signs the batch
     * with the RSU's own RSA cert. */
    gantry_log_append(rsu->gantry_id, v->obu_id, rsu->toll_cents,
                      v->time_stamp, sig, 256);
    return 0;
}


/* ---- Breakage ----
 *
 *   Factor the CSC (Concession Signing CA) RSA key:
 *     - Attacker mints OBU certs with arbitrary OBU IDs. Drives
 *       toll-free, OR generates forged passages against another
 *       vehicle's OBU-ID — fraudulent billing against random
 *       motorists at highway scale.
 *     - Settlement reconciliation between toll authorities becomes
 *       ambiguous; €10B/year EETS cross-border flows lose
 *       evidentiary footing.
 *
 *   Factor a per-OBU key:
 *     - One vehicle drives toll-free indefinitely until the CSC
 *       detects anomalous usage and blacklists the OBU ID. Minor
 *       at fleet scale; significant as a proof-of-concept that
 *       scales to the CA layer.
 *
 *   Factor an RSU firmware-signing key:
 *     - Attacker pushes malicious RSU firmware that logs false
 *       settlement data — wholesale revenue skimming with each
 *       concessionaire's reconciliation records looking valid
 *       but internally inconsistent with gantry-level signed logs.
 */
