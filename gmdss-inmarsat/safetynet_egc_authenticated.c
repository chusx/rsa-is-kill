/*
 * safetynet_egc_authenticated.c
 *
 * Inmarsat-C / FleetBroadband terminal receive path for authenticated
 * SafetyNET II EGC (Enhanced Group Call) messages. Runs on the
 * terminal's MCU firmware (ARM Cortex-M / embedded Linux on newer
 * FleetBroadband units).
 *
 * References: IMO MSC.1/Circ.1364, Inmarsat SafetyNET II Service
 * Description, IHO S-63 ed 1.2 for the companion ECDIS cell path.
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include "terminal.h"
#include "rsa_pss.h"

/* IMO-maintained trust list of MSI providers, burned into terminal
 * firmware and rotated by signed firmware updates. */
extern const struct msi_trust_entry {
    char      provider_id[16];     /* "NAVAREA-I", "METAREA-XII", "RCC-NORFOLK" */
    uint8_t   rsa_n[384];          /* RSA-3072 modulus */
    size_t    n_len;
    uint8_t   e[4];
    size_t    e_len;
    uint32_t  not_after;           /* epoch */
} MSI_TRUST_LIST[64];

extern const uint8_t INMARSAT_FW_ROOT_PUB[512];   /* terminal firmware */


/* SafetyNET II EGC frame — simplified from the ETSI EN 300 460 TDM
 * framing; the payload-auth extension carries the signature. */
struct egc_msg {
    uint16_t  c_code;              /* broadcast area / service code */
    char      provider_id[16];
    uint32_t  issued_ts;
    uint16_t  priority;            /* 3=DISTRESS, 2=URGENCY, 1=SAFETY */
    uint16_t  body_len;
    uint8_t   body[2048];          /* IA5 ASCII text of the MSI */
    uint8_t   sig[384];            /* RSA-3072 PSS-SHA256 */
    uint16_t  sig_len;
};


static const struct msi_trust_entry *
lookup_provider(const char *provider_id)
{
    for (int i = 0; i < 64; i++) {
        if (MSI_TRUST_LIST[i].n_len == 0) break;
        if (!strncmp(MSI_TRUST_LIST[i].provider_id, provider_id, 16))
            return &MSI_TRUST_LIST[i];
    }
    return NULL;
}


int egc_receive_and_authenticate(const uint8_t *raw, size_t raw_len)
{
    struct egc_msg m;
    if (egc_parse(raw, raw_len, &m) != 0) return ERR_PARSE;

    const struct msi_trust_entry *tr = lookup_provider(m.provider_id);
    if (!tr) {
        log_event("EGC rejected: unknown provider %s", m.provider_id);
        display_to_bridge("UNAUTHENTICATED MSI — IGNORED");
        return ERR_UNKNOWN_PROVIDER;
    }

    if ((uint32_t)time(NULL) > tr->not_after) {
        log_event("EGC rejected: provider cert expired %s", m.provider_id);
        return ERR_EXPIRED;
    }

    /* Hash covers everything up to the sig field. */
    uint8_t h[32];
    sha256_of(&m, offsetof(struct egc_msg, sig), h);

    if (rsa_pss_verify_sha256(tr->rsa_n, tr->n_len,
                              tr->e, tr->e_len,
                              h, 32, m.sig, m.sig_len) != 0) {
        log_event("EGC rejected: bad signature provider=%s",
                  m.provider_id);
        display_to_bridge("MSI AUTH FAILED — %s", m.provider_id);
        return ERR_BAD_SIG;
    }

    /* Authenticated — deliver to bridge printer + ECDIS overlay.
     * Under SOLAS V/19 the master is obliged to act on authenticated
     * SAR/NAV warnings. */
    display_on_ecdis_overlay(&m);
    print_to_bridge_printer(&m);
    log_event("EGC auth OK provider=%s prio=%u len=%u",
              m.provider_id, m.priority, m.body_len);
    return 0;
}


/* =========================================================
 *  S-63 ENC cell permit verify (ECDIS side)
 * ========================================================= */

struct s63_cell_permit {
    char      cell_name[8];        /* "US5NY12M" */
    uint32_t  edition;
    uint32_t  update_num;
    uint8_t   enc_key_wrapped[16]; /* cell key under HO-to-SA-wrap */
    uint8_t   sig[384];            /* RSA over cell_name|edition|key */
    uint8_t   sig_len;
};

extern const uint8_t IHO_SA_ROOT_PUB[384];   /* IHO Scheme Admin */

int s63_verify_cell_permit(const struct s63_cell_permit *p)
{
    uint8_t h[32];
    sha256_of(p, offsetof(struct s63_cell_permit, sig), h);
    return rsa_pss_verify_sha256(
        IHO_SA_ROOT_PUB, sizeof IHO_SA_ROOT_PUB,
        (uint8_t[]){0x01,0x00,0x01}, 3,
        h, 32, p->sig, p->sig_len);
}


/* =========================================================
 *  LRIT 6-hourly position report
 * ========================================================= */

int lrit_send_position_report(double lat, double lon)
{
    /* TLS mutual-auth to flag-administration LRIT Data Centre.
     * Vessel client cert is RSA-2048 leaf issued at commissioning
     * by the flag's LRIT CSP (e.g. Pole Star, CLS, Inmarsat ASP).
     * DC-to-IDE routing is a second RSA trust plane. */
    tls_session_t *t = tls_connect_mutual(
            FLAG_LRIT_DC_HOST,
            "/factory/vessel.crt",
            "/factory/vessel.key",
            FLAG_LRIT_DC_ROOT_CA, sizeof FLAG_LRIT_DC_ROOT_CA);
    if (!t) return -1;

    char payload[256];
    int n = snprintf(payload, sizeof payload,
        "{\"mmsi\":%u,\"ts\":%u,\"lat\":%.6f,\"lon\":%.6f}",
        vessel_mmsi(), (unsigned)time(NULL), lat, lon);
    tls_write(t, payload, n);
    tls_close(t);
    return 0;
}


/* ---- Breakage ---------------------------------------------
 *
 *  Factored MSI provider RSA-3072 key (e.g. NAVAREA coordinator):
 *    - Attacker signs false urgency/distress MSI; bridges treat
 *      it as authenticated per SOLAS V/19. Mass diversion of
 *      commercial traffic; denial of access to a strait.
 *
 *  Factored IHO S-63 SA root:
 *    - Forged ENC cell permits. ECDIS decrypts and displays
 *      tampered charts as authoritative. Groundings.
 *
 *  Factored terminal firmware root:
 *    - Signed firmware that silently suppresses DISTRESS-priority
 *      EGC messages or that fabricates them. GMDSS trust
 *      collapses; IMO must re-type-approve terminal firmware.
 */
