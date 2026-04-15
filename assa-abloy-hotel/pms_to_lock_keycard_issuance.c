/*
 * pms_to_lock_keycard_issuance.c
 *
 * Property-side keycard issuance and mobile-key signing, plus the
 * lock-side verification path. Pattern matches ASSA ABLOY VingCard
 * Visionline, Dormakaba Saflok System 6000, Salto ProAccess, and
 * the mobile-key backends (Hilton Digital Key via ASSA ABLOY Mobile
 * Access, Hyatt via Salto KS).
 *
 * The LIS (Lock Interface Server) runs at the property; it holds
 * the property-bound signing HSM. Front-desk encoders and mobile-
 * key issuance both route through here.
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include "hotel.h"
#include "rsa_pss.h"
#include "rsa_pkcs1v15.h"

/* Vendor root burned into every lock at factory; property sub-CA
 * installed at property-commissioning. */
extern const uint8_t VENDOR_FW_ROOT_PUB[384];
extern const uint8_t VENDOR_MOBILE_KEY_ROOT_PUB[384];
extern const uint8_t PROPERTY_PMS_CA_PUB[384];    /* PMS→LIS link */


/* =========================================================
 *  1. Property LIS — PMS-driven keycard issuance
 * ========================================================= */

struct pms_issue_request {
    char      reservation_id[32];
    char      guest_id_hash[32];      /* GDPR-friendly digest */
    uint16_t  room_no;
    uint32_t  check_in_ts;
    uint32_t  check_out_ts;
    uint8_t   perm_mask;              /* 0x01 ROOM 0x02 CLUB 0x04 POOL */
    uint8_t   sig[384];               /* PMS signs */
};

int lis_accept_pms_issue(const struct pms_issue_request *r)
{
    uint8_t h[32];
    sha256_of(r, offsetof(struct pms_issue_request, sig), h);
    if (rsa_pss_verify_sha256(
            PROPERTY_PMS_CA_PUB, sizeof PROPERTY_PMS_CA_PUB,
            (uint8_t[]){0x01,0x00,0x01}, 3,
            h, 32, r->sig, sizeof r->sig) != 0)
        return ERR_PMS_SIG;

    /* Window sanity — reject past-dated / absurdly-future windows. */
    uint32_t now = (uint32_t)time(NULL);
    if (r->check_out_ts <= r->check_in_ts) return ERR_WINDOW;
    if (r->check_out_ts < now - 3600) return ERR_WINDOW;
    if (r->check_in_ts > now + 30*86400) return ERR_WINDOW;

    /* Emit encoder payload to front-desk (RFID) + mobile-key
     * issuance record (BLE). Both carry distinct signatures. */
    issue_rfid_card_for(r);
    issue_mobile_key_record(r);
    return 0;
}


/* =========================================================
 *  2. Mobile-key signed credential
 *
 *  Delivered to the guest's phone over HTTPS to the hotel-
 *  vendor cloud, then loaded into the branded app
 *  (Hilton Honors, Marriott Bonvoy, Hyatt). BLE presentation
 *  to the door lock verifies the signature and window.
 * ========================================================= */

struct mobile_key {
    char      property_id[16];        /* "HIL-LHR-001" */
    uint16_t  room_no;
    uint32_t  valid_from, valid_to;
    uint64_t  credential_id;          /* monotonic per property */
    uint8_t   perm_mask;
    uint8_t   device_attestation[64]; /* App Attest / Play Integrity digest */
    uint8_t   property_cert[1024];    /* chains to vendor mobile-key root */
    size_t    cert_len;
    uint8_t   sig[384];
};

int lis_sign_mobile_key(struct mobile_key *k,
                        const struct pms_issue_request *r)
{
    strncpy(k->property_id, property_id(), 16);
    k->room_no      = r->room_no;
    k->valid_from   = r->check_in_ts;
    k->valid_to     = r->check_out_ts;
    k->credential_id= next_credential_id();
    k->perm_mask    = r->perm_mask;
    lis_export_property_cert(k->property_cert, sizeof k->property_cert,
                              &k->cert_len);

    uint8_t h[32];
    sha256_of(k, offsetof(struct mobile_key, sig), h);
    return rsa_pss_sign_sha256_hsm(
        LIS_PROPERTY_SIGNING_KEY,
        h, 32, k->sig, sizeof k->sig);
}


/* =========================================================
 *  3. Lock-side verification of a presented mobile key
 *
 *  Door lock MCU (Cortex-M0+ typical on VingCard Essence RFID,
 *  M4 on Allure BLE). Locks have RSA verify capability but no
 *  cloud connection — trust plane was provisioned at commissioning.
 * ========================================================= */

int lock_verify_mobile_key(const struct mobile_key *k)
{
    /* Chain property cert to vendor mobile-key root. */
    if (x509_chain_verify(k->property_cert, k->cert_len,
                          VENDOR_MOBILE_KEY_ROOT_PUB,
                          sizeof VENDOR_MOBILE_KEY_ROOT_PUB) != 0)
        return ERR_CHAIN;

    uint8_t n[384], e[4];
    size_t n_len, e_len;
    x509_extract_pub(k->property_cert, k->cert_len,
                     n, sizeof n, &n_len, e, sizeof e, &e_len);

    uint8_t h[32];
    sha256_of(k, offsetof(struct mobile_key, sig), h);
    if (rsa_pss_verify_sha256(n, n_len, e, e_len,
                              h, 32, k->sig, sizeof k->sig) != 0)
        return ERR_SIG;

    /* Property binding: this key is for THIS property. Locks are
     * factory-configured with their property-id; mis-property
     * credentials reject. */
    if (strncmp(k->property_id, lock_property_id(), 16))
        return ERR_WRONG_PROPERTY;

    /* Room binding. Master/staff credentials have room_no=0xFFFF
     * with a role bit set. */
    if (k->room_no != 0xFFFF && k->room_no != lock_room_no())
        return ERR_WRONG_ROOM;

    /* Window. Lock uses its battery-backed RTC. */
    uint32_t now = lock_rtc_now();
    if (now < k->valid_from || now > k->valid_to)
        return ERR_OUT_OF_WINDOW;

    /* Replay: monotonic credential id per property — lock tracks
     * the most recent ~128 ids per room to reject re-presentation
     * after checkout even if the clock is tolerant. */
    if (lock_has_seen_credential(k->credential_id))
        return ERR_REPLAY;

    lock_remember_credential(k->credential_id);
    lock_unlatch_motor();
    audit_log_append("ENTRY room=%u cred=%llu",
                     k->room_no, (unsigned long long)k->credential_id);
    return 0;
}


/* =========================================================
 *  4. Lock firmware update (carried via cleaning-card OTA)
 * ========================================================= */

int lock_apply_fw_update(const uint8_t *pkg, size_t len)
{
    struct fw_manifest {
        char model[16]; char build[24]; uint32_t rollback;
        uint8_t img_sha256[32]; uint8_t sig[384];
    } *m = parse_fw_manifest(pkg, len);

    if (m->rollback < otp_rollback()) return ERR_ROLLBACK;

    uint8_t h[32];
    sha256_of(m, offsetof(struct fw_manifest, sig), h);
    if (rsa_pss_verify_sha256(
            VENDOR_FW_ROOT_PUB, sizeof VENDOR_FW_ROOT_PUB,
            (uint8_t[]){0x01,0x00,0x01}, 3,
            h, 32, m->sig, sizeof m->sig) != 0)
        return ERR_FW_SIG;

    flash_stage_and_swap(pkg, len);
    return 0;
}


/* ---- Breakage ---------------------------------------------
 *
 *  VENDOR_FW_ROOT factored (ASSA ABLOY / Dormakaba / Salto):
 *    - Signed firmware pushed via the cleaning-card OTA path to
 *      millions of hotel locks; attacker installs a silent
 *      skeleton-key trigger. Universal room access across a
 *      vendor's global portfolio.
 *
 *  VENDOR_MOBILE_KEY_ROOT factored:
 *    - Attacker mints a "property cert", signs arbitrary mobile
 *      keys for any room at any brand-portfolio property. BLE
 *      entry with no PMS-side audit trail.
 *
 *  PROPERTY_PMS_CA factored:
 *    - Forged PMS issue requests at a single property; front
 *      desk emits real keycards for rooms occupied by paying
 *      guests.
 *
 *  Cloud-fleet CA factored (Salto KS / Latch / Brivo):
 *    - Dynamic universal-unlock against commercial tenants,
 *      multifamily residential, hospital back-of-house.
 */
