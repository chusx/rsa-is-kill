/*
 * hotel_key_provisioning.c
 *
 * ASSA ABLOY Vingcard Visionline / Dormakaba Saflok / SALTO
 * hotel electronic lock key provisioning. The front-desk PMS
 * (Property Management System: Opera / Mews / Protel) issues
 * a signed keycard-definition to the lock encoder, which writes
 * the MIFARE DESFire / SEOS credential. The keycard-definition
 * is signed by the property's master key, which chains to the
 * ASSA ABLOY provisioning root (RSA-2048).
 *
 * A factored provisioning root -> forge any guest keycard for
 * any property using that lock system worldwide.
 */

#include <stdint.h>
#include <string.h>
#include "vingcard.h"

extern const uint8_t ASSA_PROVISIONING_ROOT_PUB[384];

struct keycard_def {
    char       property_id[12];
    uint16_t   room_number;
    uint64_t   valid_from;
    uint64_t   valid_to;
    uint8_t    guest_id[16];
    uint8_t    access_zones;           /* room + pool + gym etc.  */
    uint8_t    master_override;        /* 0=guest, 1=staff, 2=master*/
    uint8_t    pms_cert[2048]; size_t pms_cert_len;
    uint8_t    sig[384];
};

int lock_accept_keycard(const struct keycard_def *k)
{
    if (x509_chain_verify(k->pms_cert, k->pms_cert_len,
            ASSA_PROVISIONING_ROOT_PUB,
            sizeof ASSA_PROVISIONING_ROOT_PUB))
        return LOCK_CHAIN;
    uint8_t h[32];
    sha256_of(k, offsetof(struct keycard_def, pms_cert), h);
    if (verify_with_cert(k->pms_cert, k->pms_cert_len,
                         h, k->sig, sizeof k->sig))
        return LOCK_SIG;
    if (now_ns() < k->valid_from || now_ns() > k->valid_to)
        return LOCK_EXPIRED;
    return lock_grant_access(k->room_number, k->access_zones);
}

/* ---- Physical intrusion at hospitality scale ---------------
 *  ASSA_PROVISIONING_ROOT factored: mint a master_override=2
 *  keycard valid for any room at any property using Vingcard.
 *  Silent; lock audit log shows "valid keycard." Recovery:
 *  ASSA ABLOY ships new provisioning root + every lock's trust
 *  store updated. Millions of locks globally; firmware update
 *  via NFC one-by-one or BLE-mesh per-property.
 * --------------------------------------------------------- */
