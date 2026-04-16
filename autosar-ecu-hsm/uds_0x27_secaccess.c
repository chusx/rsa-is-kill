/*
 * uds_0x27_secaccess.c
 *
 * UDS (ISO 14229-1) Service $27 Security Access — the handshake
 * that must precede any ECU reprogramming ($34/$36/$37), routine
 * activation ($31 RID FF00 = erase flash), or ECU reset.
 *
 * On AUTOSAR 4.x ECUs with an HSM (Bosch Gen3 / Infineon Aurix
 * HSM / Renesas ICU-S), the "security access" challenge is no
 * longer XOR/CRC — it is an RSA-PSS signature over a server-side
 * nonce plus the ECU's ECUID, verified against a tool/OEM public
 * key fused into the HSM at line-of-assembly provisioning.
 *
 * This is the layer where an attacker with a factored OEM RSA
 * tool-authorization key turns scan-tool-diagnostic access into
 * unlocked bootloader and arbitrary ECU re-flash.
 */

#include <stdint.h>
#include <string.h>
#include "uds.h"
#include "hsm.h"

/* OEM-provisioned in HSM NVRAM during line-of-assembly; ships in
 * every vehicle of this platform. Hundreds of thousands to tens of
 * millions of units per OEM program. */
extern const uint8_t OEM_TOOL_AUTH_ROOT_PUB[384];   /* RSA-3072 */

#define UDS_SID_SECURITY_ACCESS  0x27
#define UDS_SID_REQUEST_DL       0x34
#define UDS_SID_TRANSFER_DATA    0x36
#define UDS_SID_TRANSFER_EXIT    0x37
#define UDS_SID_ROUTINE_CTRL     0x31

/* Security level maps defined by OEM CDD (e.g. VW 80300,
 * BMW GS 95010-1, Stellantis GSEP 00 026). */
enum sec_level {
    SEC_LEVEL_DEV_UNLOCK    = 0x01,   /* flashing, RID FF00 erase */
    SEC_LEVEL_ODX_PROG      = 0x03,   /* production programming   */
    SEC_LEVEL_FAC_BOOTLDR   = 0x11,   /* factory bootloader       */
    SEC_LEVEL_FIELD_REFLASH = 0x61,   /* dealer workshop          */
};

struct seed_response {
    uint8_t  sid;                      /* 0x67 */
    uint8_t  sub;                      /* level | 0x80  reply bit */
    uint8_t  ecu_serial[12];           /* binds nonce to this ECU */
    uint32_t seed_ctr;                 /* per-ECU monotonic       */
    uint8_t  nonce[32];                /* TRNG, anti-replay       */
};

/* Tool constructs a signed reply: (ecu_serial || seed_ctr ||
 * nonce || requested_level) under OEM_TOOL_AUTH_ROOT priv key.
 * HSM verifies with the fused pubkey. No pre-shared secret. */
struct key_response {
    uint8_t  sid;                      /* 0x27 */
    uint8_t  sub;                      /* level (odd = key)       */
    uint8_t  ecu_serial[12];
    uint32_t seed_ctr;
    uint8_t  nonce[32];
    uint8_t  requested_level;
    uint8_t  tool_cert[1024];  size_t tool_cert_len;
    uint8_t  sig[384];                 /* RSA-PSS-SHA256          */
};

int uds_27_request_seed(enum sec_level lvl, struct seed_response *r)
{
    if (!allowed_in_session(lvl)) return NRC_CONDITIONS_NOT_CORRECT;

    r->sid = 0x67;
    r->sub = lvl;
    memcpy(r->ecu_serial, hsm_ecu_serial(), 12);
    r->seed_ctr = hsm_seed_counter_next();
    trng_fill(r->nonce, 32);
    /* Cached in HSM scratch; consumed by matching $27 key msg. */
    hsm_stash_seed(r);
    return 0;
}

int uds_27_send_key(const struct key_response *k)
{
    struct seed_response *s = hsm_lookup_seed(k->seed_ctr);
    if (!s) return NRC_REQUEST_SEQUENCE_ERROR;

    if (memcmp(k->ecu_serial, s->ecu_serial, 12) ||
        memcmp(k->nonce, s->nonce, 32))
        return NRC_SECURITY_ACCESS_DENIED;

    /* (1) Validate tool cert chains to OEM_TOOL_AUTH_ROOT_PUB.
     * Cert carries the maximum level this tool is authorized for;
     * a field-service tool cert cannot be used for FAC_BOOTLDR. */
    uint16_t max_lvl;
    if (x509_verify_and_extract_level(
            k->tool_cert, k->tool_cert_len,
            OEM_TOOL_AUTH_ROOT_PUB, sizeof OEM_TOOL_AUTH_ROOT_PUB,
            &max_lvl))
        return NRC_SECURITY_ACCESS_DENIED;
    if (k->requested_level > max_lvl)
        return NRC_SECURITY_ACCESS_DENIED;

    /* (2) Verify signature over (ecu_serial||seed_ctr||nonce||level). */
    uint8_t h[32];
    struct {
        uint8_t ecu[12]; uint32_t ctr; uint8_t nonce[32]; uint8_t lvl;
    } tbs;
    memcpy(tbs.ecu, k->ecu_serial, 12);
    tbs.ctr = k->seed_ctr;
    memcpy(tbs.nonce, k->nonce, 32);
    tbs.lvl = k->requested_level;
    sha256(&tbs, sizeof tbs, h);

    if (verify_with_cert(k->tool_cert, k->tool_cert_len,
                         h, k->sig, sizeof k->sig))
        return NRC_SECURITY_ACCESS_DENIED;

    /* (3) Rate-limit: 3 bad attempts -> 10 s lockout (ISO 14229) */
    hsm_clear_attempt_counter();
    hsm_set_session_level(k->requested_level);
    return 0;
}

/* =========================================================
 *  Subsequent $34/$36/$37 programming gate checks
 *  hsm_session_level() before accepting flash writes. The
 *  actual flash image is ALSO RSA-PSS signed (see
 *  secure_boot_chain.c in this directory) — but the write
 *  permission itself is gated by $27.
 * ========================================================= */

int uds_34_request_download(uint32_t addr, uint32_t len)
{
    if (hsm_session_level() < SEC_LEVEL_DEV_UNLOCK)
        return NRC_SECURITY_ACCESS_DENIED;
    return flash_bl_open(addr, len);
}

/* ---- Break surface when OEM_TOOL_AUTH_ROOT factored --------
 * Attacker recovers the OEM tool-auth RSA private key from
 * published scan-tool cert chains (every dealer workshop's
 * MVCI tool ships the cert). Mint a tool cert with max_lvl =
 * SEC_LEVEL_FAC_BOOTLDR, sign the $27 key response, unlock
 * the ECU, then push an attacker-signed flash image (break
 * of the second RSA key in secure_boot_chain.c unlocks that).
 * Fleet-wide abuse requires only CAN/DoIP reach — any OBD-II
 * port / telematics unit with UDS passthrough suffices.
 * --------------------------------------------------------- */
