/*
 * receiver_app_and_aea.c
 *
 * ATSC 3.0 receiver-side handling of signed broadcast applications
 * (A/344) and Advanced Emergency Alerts (A/331 + A/341). Runs on
 * the TV's broadcast-stack SoC firmware (typically Linux + Android
 * TV stack on Samsung/LG/Sony/TCL; webOS on LG).
 *
 * Only the signature/verification plane is modelled here; the MMT
 * / ROUTE-DASH transport, A/V decoder pipeline, and UI layer are
 * elsewhere.
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include "atsc3.h"
#include "rsa_pkcs1v15.h"
#include "rsa_pss.h"
#include "x509.h"

/* ATSC-maintained trust list: broadcaster signing intermediates
 * chained to the ATSC root. Shipped in TV firmware; rotated via
 * signed OTA. */
extern const uint8_t ATSC_APP_ROOT_PUB[512];      /* RSA-4096 */
extern const uint8_t ATSC_AEA_ROOT_PUB[512];      /* RSA-4096 */
extern const uint8_t OEM_FW_ROOT_PUB[512];


/* =========================================================
 *  1. Signed broadcast application verify (A/344)
 * ========================================================= */

struct broadcast_app_manifest {
    char      bsid[8];                /* broadcast stream id */
    char      app_id[64];
    char      version[16];
    uint32_t  not_before;
    uint32_t  not_after;
    uint8_t   bundle_sha256[32];      /* zip-of-HTML+JS+assets */
    uint8_t   broadcaster_cert[2048]; /* chain to ATSC root */
    size_t    cert_len;
    uint8_t   sig[512];               /* RSA-4096 over the above */
};

int verify_and_launch_broadcast_app(
        const struct broadcast_app_manifest *m,
        const uint8_t *bundle, size_t bundle_len)
{
    /* Time window. */
    uint32_t now = (uint32_t)time(NULL);
    if (now < m->not_before || now > m->not_after) return ERR_APP_TIME;

    /* Content integrity against manifest. */
    uint8_t h[32];
    sha256(bundle, bundle_len, h);
    if (memcmp(h, m->bundle_sha256, 32)) return ERR_APP_BODY;

    /* Extract broadcaster pubkey + chain-verify to ATSC app root. */
    uint8_t n[512], e[4];
    size_t n_len, e_len;
    if (x509_chain_verify(m->broadcaster_cert, m->cert_len,
                          ATSC_APP_ROOT_PUB,
                          sizeof ATSC_APP_ROOT_PUB) != 0)
        return ERR_APP_CHAIN;
    if (x509_extract_pub(m->broadcaster_cert, m->cert_len,
                         n, sizeof n, &n_len,
                         e, sizeof e, &e_len) != 0)
        return ERR_APP_PUB;

    /* Verify the manifest signature with the broadcaster's key. */
    sha256_of(m, offsetof(struct broadcast_app_manifest, sig), h);
    if (rsa_pss_verify_sha256(n, n_len, e, e_len,
                              h, 32, m->sig, sizeof m->sig) != 0)
        return ERR_APP_SIG;

    /* Sandboxed Chrome WebView launched with CSP locking network
     * egress to broadcaster-declared origins only. */
    return launch_sandboxed_app(m->app_id, bundle, bundle_len);
}


/* =========================================================
 *  2. Advanced Emergency Alert (AEA) verify + surface
 * ========================================================= */

struct aea_message {
    char      aea_id[32];
    char      issuer[32];             /* "FEMA-IPAWS", "NWS", "LOCAL-EOC" */
    uint8_t   priority;               /* 0=LOW 1=HIGH 2=EXTREME 3=PRESIDENTIAL */
    uint32_t  issued_ts;
    uint32_t  effective_until;
    char      headline[96];
    char      description[512];
    uint32_t  polygon_len;            /* affected area CAP polygon */
    uint8_t   polygon[2048];
    uint8_t   issuer_cert[2048];
    size_t    cert_len;
    uint8_t   sig[512];
};

int aea_ingest(const struct aea_message *a)
{
    uint32_t now = (uint32_t)time(NULL);
    if (now > a->effective_until) return ERR_AEA_STALE;

    uint8_t h[32];

    /* Chain to ATSC AEA root — which is cross-signed from FEMA
     * IPAWS / NWS / state-EOC issuer hierarchy. */
    if (x509_chain_verify(a->issuer_cert, a->cert_len,
                          ATSC_AEA_ROOT_PUB,
                          sizeof ATSC_AEA_ROOT_PUB) != 0)
        return ERR_AEA_CHAIN;

    uint8_t n[512], e[4];
    size_t n_len, e_len;
    x509_extract_pub(a->issuer_cert, a->cert_len,
                     n, sizeof n, &n_len, e, sizeof e, &e_len);

    sha256_of(a, offsetof(struct aea_message, sig), h);
    if (rsa_pss_verify_sha256(n, n_len, e, e_len,
                              h, 32, a->sig, sizeof a->sig) != 0) {
        /* Unauthenticated alerts must not render as authoritative.
         * Log and surface as "unverified" only if operator policy
         * allows (most operators suppress entirely). */
        log_event("AEA_SIG_BAD issuer=%s aea=%s", a->issuer, a->aea_id);
        return ERR_AEA_SIG;
    }

    /* Presidential-priority overrides mute; forces volume and
     * cross-input interrupt per FCC 47 CFR §10.520. */
    render_emergency_crawl_and_interrupt(a);

    /* Push to companion devices (Android/iOS ATSC 3.0 companion
     * apps) over local-net. */
    broadcast_to_companion_devices(a);
    return 0;
}


/* =========================================================
 *  3. OEM TV firmware OTA path
 * ========================================================= */

int tv_apply_firmware_ota(const uint8_t *pkg, size_t len)
{
    struct fw_manifest { /* abbreviated */
        char product[32]; char build[32]; uint32_t rollback_idx;
        uint8_t system_sha256[32]; uint8_t atsc3_sha256[32];
        uint8_t sig[512];
    } *m = parse_fw_manifest(pkg, len);

    if (m->rollback_idx < otp_read_rollback()) return ERR_ROLLBACK;

    uint8_t h[32];
    sha256_of(m, offsetof(struct fw_manifest, sig), h);
    if (rsa_pkcs1v15_verify_sha256(
            OEM_FW_ROOT_PUB, sizeof OEM_FW_ROOT_PUB,
            (uint8_t[]){0x01,0x00,0x01}, 3,
            h, 32, m->sig, sizeof m->sig) != 0)
        return ERR_FW_SIG;

    stage_firmware_and_reboot(pkg, len);
    return 0;
}


/* ---- Breakage ---------------------------------------------
 *
 *   ATSC_APP_ROOT factored:
 *     - Rogue RF injection delivers a signed malicious
 *       interactive app that runs on every TV in a market;
 *       cross-companion-device exfil, exploitation of the
 *       broadband return path.
 *
 *   ATSC_AEA_ROOT factored:
 *     - Signed false "tsunami / shelter-in-place / presidential"
 *       alert delivered to every TV in the footprint. Mass
 *       panic. Long-term public trust in the emergency-alerting
 *       infrastructure collapses.
 *
 *   OEM_FW_ROOT factored (Samsung / LG / Sony / TCL):
 *     - Fleet-scale bricking, or conversion of TVs into a DDoS /
 *       residential-proxy botnet. OTA-push reach is ~60M+ US
 *       households per major OEM.
 */
