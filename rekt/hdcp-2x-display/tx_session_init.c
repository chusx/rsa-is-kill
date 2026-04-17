/*
 * tx_session_init.c
 *
 * HDCP 2.3 (2.x generation) transmitter session initialization in
 * display-pipeline firmware. Sits alongside the AKE RSA primitive in
 * `hdcp2_ake_rsa.c` and shows how it threads into the actual link
 * bring-up: HPD detect → EDID read → HDCP capability probe →
 * authentication → locality check → session-key exchange → stream-key
 * derivation → content scrambling.
 *
 * Deployed in:
 *   - Every HDMI 2.0/2.1 source: Apple TV 4K, Roku Ultra, Shield TV,
 *     Xbox Series X, PlayStation 5, Bluray players (Sony, Panasonic,
 *     LG), 4K set-top-boxes from Comcast, Sky Q, Samsung TV Plus
 *   - Every DisplayPort 1.3+ source: nVidia RTX, AMD Radeon, Intel Arc,
 *     M-series Mac SoC (Apple M3/M4 display controller)
 *   - Pro AV routers/matrix from Crestron, Extron, Kramer.
 *
 * The DCP LLC RSA key hierarchy underneath dates to 2008 and operates
 * across consumer A/V distribution globally.
 */

#include <stdint.h>
#include <string.h>
#include "hdcp2.h"
#include "dcp_llc_root.h"


struct hdcp2_tx {
    uint32_t link_id;
    int      is_hdmi;               /* else DP */
    uint8_t  rx_public_cert[522];   /* "Certrx": ReceiverID || Kpubrx(n+e) || DCP_LLC_sig */
    uint8_t  km[16];                /* master secret */
    uint8_t  ks[16];                /* session key */
    uint8_t  riv[8];                /* stream-counter IV */
    uint64_t rx_receiver_id;        /* 40 bits; used for revocation check */
    int      repeater_depth;
    int      is_authenticated;
};


int
hdcp2_tx_bring_up(struct hdcp2_tx *tx)
{
    /* 1.  HPD low->high, DDC read EDID, detect HDCP2-capable Rx. */
    if (!sink_supports_hdcp2(tx)) return HDCP2_DOWNGRADE_OR_BLANK;

    /* 2.  AKE_Init (Tx -> Rx): random 64-bit rtx + TxCaps.
     *     Rx responds with its signed Cert-rx + 64-bit rrx + RxCaps.
     *     The cert carries the Rx public RSA-3072 key signed by DCP
     *     LLC RSA-3072 root. */
    if (hdcp2_ake_init(tx)                    != 0) return HDCP2_LINK_FAIL;
    if (hdcp2_ake_send_cert_receive(tx)       != 0) return HDCP2_LINK_FAIL;

    /* 3.  Verify Cert-rx under the pinned DCP LLC root + check the
     *     ReceiverID against the System Renewability Message (SRM) —
     *     the DCP LLC–signed revocation list distributed in content
     *     streams (BD-ROM, broadcast streams, Netflix/Prime DRM
     *     payloads) and periodically refreshed in source firmware. */
    if (hdcp2_verify_rx_cert_rsa(tx)          != 0) return HDCP2_LINK_FAIL;
    if (srm_is_revoked(tx->rx_receiver_id))         return HDCP2_REVOKED;

    /* 4.  No-stored-Km path: Tx picks Km, RSA-OAEP encrypts under
     *     Rx's pubkey, sends H-prime / L-prime pairing proof.  This
     *     is the core RSA operation protected by the factoring
     *     assumption — `hdcp2_ake_rsa.c::hdcp2_ake_encrypt_km`. */
    if (hdcp2_ake_pick_and_encrypt_km(tx)     != 0) return HDCP2_LINK_FAIL;
    if (hdcp2_ake_verify_H_prime(tx)          != 0) return HDCP2_LINK_FAIL;

    /* 5.  Locality Check (LC_Init / L_prime): 20ms bound enforced
     *     to prevent long-haul repeater cascades. */
    if (hdcp2_locality_check(tx)              != 0) return HDCP2_LINK_FAIL;

    /* 6.  Session Key Exchange: Tx generates Ks, AES-wraps under Km,
     *     Tx + Rx derive authStreamCtr / inputCtr / outputCtr. */
    if (hdcp2_ske_send(tx)                    != 0) return HDCP2_LINK_FAIL;

    /* 7.  Repeater Auth (only if Rx is a repeater/AVR). Propagates
     *     downstream ReceiverIDs upstream; source re-runs SRM check. */
    if (tx->repeater_depth &&
        hdcp2_repeater_auth(tx)               != 0) return HDCP2_LINK_FAIL;

    tx->is_authenticated = 1;

    /* 8.  Tell the display pipeline to enable AES-128-CTR scrambling
     *     using Ks on every active sub-stream (main video + audio +
     *     metadata; DP-MST sub-streams each get their own key
     *     derivation). */
    display_pipeline_enable_cipher(tx->link_id, tx->ks, tx->riv);
    return 0;
}


/* Breakage:
 *
 * HDCP 2.x authenticates every receiver's RSA-3072 device cert
 * against the DCP LLC RSA-3072 root.  An RSA factoring attack on
 * that root lets an attacker mint *unrevokable* receiver certs
 * that every HDCP2-capable source on Earth accepts — fully bypassing
 * the content-protection layer for 4K/8K premium streaming.
 * Netflix UHD, Dolby Vision, Apple TV+, Disney+, Amazon Prime UHD
 * all condition their top-quality bitstreams on HDCP2 authentication
 * before unblanking.  The same break also enables forging source
 * certs, so sinks can be convinced they're connected to a legitimate
 * studio-approved master reference display — relevant for leaked
 * pre-release theatrical content.
 */
