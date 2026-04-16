/*
 * osdp_key_exchange.c
 *
 * SIA OSDP v2 (Open Supervised Device Protocol) + HID SEOS
 * reader-to-controller key exchange. OSDP v2's Secure Channel
 * Protocol (SCP) uses RSA-2048 for reader identity and initial
 * key agreement between the reader (HID iCLASS SE, Mercury LP,
 * Axis A1001) and the access-control panel (Mercury EP, Lenel
 * S2, Genetec Synergis).
 *
 * The reader's RSA cert is provisioned at the factory by HID /
 * ASSA ABLOY; the panel verifies it against HID's manufacturing
 * CA. Session keys for AES-128 encryption and MAC are derived
 * from the RSA handshake. This is the layer protecting card-
 * reader <-> panel traffic — i.e. the decision of whether a
 * door opens or stays locked.
 */

#include <stdint.h>
#include <string.h>
#include "osdp.h"

extern const uint8_t HID_MANUFACTURING_CA_PUB[384];

struct osdp_scp_init {
    uint8_t  reader_uid[8];
    uint8_t  reader_cert[2048]; size_t reader_cert_len;
    uint8_t  nonce_reader[16];
    uint8_t  nonce_panel[16];
    uint8_t  reader_sig[256];          /* RSA-PKCS1v15-SHA256     */
};

int panel_accept_reader(const struct osdp_scp_init *s,
                        struct osdp_session *sess)
{
    if (x509_chain_verify(s->reader_cert, s->reader_cert_len,
            HID_MANUFACTURING_CA_PUB,
            sizeof HID_MANUFACTURING_CA_PUB))
        return OSDP_CHAIN;

    uint8_t tbs[8+16+16];
    memcpy(tbs, s->reader_uid, 8);
    memcpy(tbs+8, s->nonce_reader, 16);
    memcpy(tbs+24, s->nonce_panel, 16);
    uint8_t h[32]; sha256(tbs, sizeof tbs, h);
    if (verify_with_cert(s->reader_cert, s->reader_cert_len,
                         h, s->reader_sig, 256))
        return OSDP_SIG;

    /* Derive session keys from (nonce_reader || nonce_panel)
     * using HKDF-SHA256. Session keys protect all subsequent
     * card-read events. */
    derive_session_keys(s->nonce_reader, s->nonce_panel,
                        sess->enc_key, sess->mac_key);
    return OSDP_OK;
}

/* ---- Physical access control compromise --------------------
 *  HID_MANUFACTURING_CA factored:
 *    Forge a reader cert -> impersonate any reader to any
 *    panel. The panel now trusts an attacker-built "reader"
 *    (SDR + microcontroller) which can:
 *      * Report forged card-read events (badge number of any
 *        employee) -> panel unlocks the door.
 *      * Suppress real card reads (DoS on physical access).
 *      * Harvest credentials from legitimate card taps if
 *        also MitM'ing the real reader.
 *    Every OSDP v2 installation with HID readers is exposed.
 *  Recovery: HID issues new manufacturing CA; every reader +
 *  panel re-provisioned. Enterprise campus: thousands of
 *  readers, each requiring a technician visit.
 * --------------------------------------------------------- */
