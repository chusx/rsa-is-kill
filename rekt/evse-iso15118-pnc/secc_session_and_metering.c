/*
 * secc_session_and_metering.c
 *
 * Charger-side SECC (Supply Equipment Communication Controller):
 * TLS handshake, contract-cert chain verify, AuthorizationReq
 * signature verify, Eichrecht-signed metering receipt emission.
 * Pattern: ABB Terra HP / Alpitronic HYC / ChargePoint Express.
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include "secc.h"
#include "rsa_pss.h"

extern const uint8_t V2G_ROOT_PUB[384];


/* =========================================================
 *  1. TLS handshake — mutual RSA
 * ========================================================= */

int secc_tls_accept_evcc(int sock, struct evcc_session *s)
{
    /* ISO 15118-2 pins the cipher suite to RSA-based key agreement.
     * -20 permits ECDHE; for -2 peers we accept RSA KEX.
     */
    if (tls_accept_with_cert(sock, SECC_CERT_CHAIN,
                             SECC_KEY, V2G_ROOT_PUB,
                             sizeof V2G_ROOT_PUB,
                             &s->tls) != 0)
        return ERR_TLS;

    if (tls_peer_leaf(&s->tls, s->evcc_cert,
                      sizeof s->evcc_cert, &s->evcc_cert_len) != 0)
        return ERR_NO_EVCC_CERT;

    return 0;
}


/* =========================================================
 *  2. Contract-cert chain verify during AuthorizationReq
 * ========================================================= */

struct authorization_req {
    uint8_t   gen_challenge[16];      /* SECC random */
    uint8_t   contract_cert[1536];    /* leaf */
    size_t    contract_cert_len;
    uint8_t   contract_chain[4096];   /* OEM provisioning + MO sub-CA */
    size_t    chain_len;
    uint8_t   sig[256];               /* EVCC signs gen_challenge */
};

int secc_verify_authorization(const struct authorization_req *ar)
{
    if (x509_chain_verify(ar->contract_chain, ar->chain_len,
                          V2G_ROOT_PUB, sizeof V2G_ROOT_PUB) != 0)
        return ERR_CHAIN;
    if (x509_issued_by(ar->contract_cert, ar->contract_cert_len,
                       ar->contract_chain, ar->chain_len) != 0)
        return ERR_LEAF_ISSUER;

    uint8_t n[384], e[4];
    size_t n_len, e_len;
    x509_extract_pub(ar->contract_cert, ar->contract_cert_len,
                     n, sizeof n, &n_len, e, sizeof e, &e_len);

    /* XMLDSig canonicalisation of the AuthorizationReq minus sig */
    uint8_t h[32];
    xmldsig_c14n_hash(ar, offsetof(struct authorization_req, sig), h);

    if (rsa_pss_verify_sha256(n, n_len, e, e_len, h, 32,
                              ar->sig, sizeof ar->sig) != 0)
        return ERR_AUTH_SIG;

    /* Check contract cert not on CRL — refreshed per Hubject OCP */
    if (contract_cert_revoked(ar->contract_cert, ar->contract_cert_len))
        return ERR_REVOKED;
    return 0;
}


/* =========================================================
 *  3. Eichrecht / AFIR signed metering receipt
 * ========================================================= */

struct metering_receipt {
    char      charger_id[20];
    char      session_id[32];
    char      contract_id[32];        /* EMAID */
    uint32_t  start_ts, stop_ts;
    uint64_t  start_meter_wh;
    uint64_t  stop_meter_wh;
    uint32_t  meter_public_key_id;    /* sealed calibration key */
    uint8_t   sig[384];               /* RSA-3072 PSS, Eichrecht */
};

int secc_emit_metering_receipt(struct metering_receipt *mr)
{
    mr->stop_ts = (uint32_t)time(NULL);
    mr->stop_meter_wh = meter_read_sealed();

    uint8_t h[32];
    sha256_of(mr, offsetof(struct metering_receipt, sig), h);
    /* Signing happens inside the sealed meter module — the meter
     * itself is the evidentiary root under Eichrecht; the charger
     * merely transports the signed payload. */
    if (sealed_meter_sign(mr, h, 32, mr->sig, sizeof mr->sig) != 0)
        return ERR_METER_SIGN;

    /* Publish to driver's app via the backend; Transparenzsoftware
     * verifies chain independently of the billing provider. */
    return csms_post_receipt(mr);
}


/* =========================================================
 *  4. OCPP firmware update signature verify
 * ========================================================= */

int secc_accept_firmware(const uint8_t *fw, size_t len,
                         const uint8_t *sig, size_t sig_len)
{
    uint8_t h[32];
    sha256_mem(fw, len, h);
    return rsa_pss_verify_sha256(
        CHARGER_OEM_FW_PUB, sizeof CHARGER_OEM_FW_PUB,
        (uint8_t[]){0x01,0x00,0x01}, 3,
        h, 32, sig, sig_len);
}


/* ---- Breakage ---------------------------------------------
 *
 *  V2G Root factored:
 *    - Attacker issues forged mobility-operator sub-CA, mints
 *      contract certs against any EMAID. Fleet-scale billing
 *      fraud; clearing-house settlements collapse.
 *
 *  OEM Provisioning CA factored:
 *    - All vehicles of that OEM vulnerable to contract-cert
 *      impersonation; automaker ends up liable under roaming
 *      agreements.
 *
 *  Charger OEM firmware root factored:
 *    - Rogue firmware on fleet — deliberate outage, pricing
 *      manipulation, or worse (unsafe charging profiles on
 *      battery packs).
 *
 *  Sealed-meter Eichrecht key factored:
 *    - Consumer-protection evidentiary chain collapses; driver
 *      cannot independently verify the kWh billed.
 */
