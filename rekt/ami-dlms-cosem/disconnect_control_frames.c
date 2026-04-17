/*
 * disconnect_control_frames.c
 *
 * DLMS/COSEM (IEC 62056) command encoding for the
 * Disconnect_control interface class (IC 70) — the smart
 * meter interface that physically opens the service-entrance
 * contactor to disconnect a premise's electricity.
 *
 * In most utility deployments (Landis+Gyr E350/E450, Itron
 * Gen5, Kamstrup OMNIA), the Disconnect_control methods are
 * protected by "HLS-5 with digital signature" (COSEM blue
 * book §9.4.2.7.4) — the command is accompanied by an
 * ECDSA or RSA-PSS signature over the invocation_counter and
 * method_invocation_parameters, verified by the meter's HSM
 * against the utility back-office signing key.
 *
 * A factored utility back-office RSA key therefore gives
 * fleet-wide ability to open every service contactor in the
 * AMI region simultaneously — a grid-scale load-rejection
 * event with cascading stability consequences.
 */

#include <stdint.h>
#include <string.h>
#include "dlms.h"
#include "cosem.h"

extern const uint8_t UTILITY_BACKOFFICE_PUB[256];    /* RSA-2048 */

/* COSEM OBIS code for Disconnect_control (clause B.4.10):
 *    0-0:96.3.10.255   "logical_name"
 *  Class ID 70, methods:
 *    1  remote_disconnect
 *    2  remote_reconnect  (only in "remote" mode; else manual)
 */

#define OBIS_DISCONNECT_CTRL    "\x00\x00\x60\x03\x0A\xFF"
#define CLASS_ID_DISCONNECT_CTRL 70

enum disc_state {
    DISC_CONNECTED       = 0,
    DISC_DISCONNECTED    = 1,
    DISC_READY_FOR_RECON = 2,
};

enum disc_ctl_mode {
    CTL_NONE = 0,           /* cannot be disconnected          */
    CTL_MANUAL = 1,
    CTL_REMOTE = 2,         /* <- the attackable mode          */
    CTL_CUSTOMER = 3,       /* customer can reconnect manually */
    CTL_CUSTOMER_MANUAL_RECON = 4,
    CTL_REMOTE_AND_CUSTOMER = 6,
};

/* AARE (associate response) must have established ACCESS_LEVEL
 * "management_client" or "firmware_update_client" — else the
 * meter refuses the method call outright. Authentication at
 * AARQ time already uses HLS-5 challenge/response. */
struct method_request_action {
    uint8_t   tag;                  /* 0xC3  action.request  */
    uint8_t   invoke_id;
    uint16_t  class_id;             /* 70                     */
    uint8_t   obis[6];              /* 0-0:96.3.10.255        */
    uint8_t   method_id;            /* 1 = disconnect         */
    /* method-specific parameter list (octet-string, variable) */
    uint8_t   params[0];
};

/* HLS-5 with digital signature wrapper (Green Book §9.2.8.10
 * authenticated-request APDU). The sig is over invocation_ctr
 * || serverSysTitle || clientSysTitle || plaintext-xDLMS-APDU. */
struct auth_apdu {
    uint8_t   ctrl_byte;            /* 0x31 (auth+cipher)     */
    uint32_t  invocation_ctr;       /* monotonic per server   */
    uint8_t   plaintext[256];
    size_t    plaintext_len;
    uint8_t   sig[256];             /* RSA-PSS-SHA256         */
};

/* Back-office-initiated disconnect; shown as the "what goes
 * over the air" when a billing-delinquent account is cut. */
int meter_process_disconnect(const struct auth_apdu *a,
                             const uint8_t srv_syst[8],
                             const uint8_t clt_syst[8])
{
    if (a->invocation_ctr <= meter_read_inv_ctr())
        return DLMS_REPLAY;

    /* Verify the HLS-5 sig over (ic||ss||cs||apdu). */
    uint8_t tbs[4+8+8+256];
    write_be32(tbs, a->invocation_ctr);
    memcpy(tbs+4, srv_syst, 8);
    memcpy(tbs+12, clt_syst, 8);
    memcpy(tbs+20, a->plaintext, a->plaintext_len);

    uint8_t h[32];
    sha256(tbs, 20 + a->plaintext_len, h);
    if (rsa_pss_verify_sha256(UTILITY_BACKOFFICE_PUB,
            sizeof UTILITY_BACKOFFICE_PUB,
            (uint8_t[]){1,0,1}, 3, h, 32,
            a->sig, sizeof a->sig))
        return DLMS_AUTH_FAIL;

    meter_update_inv_ctr(a->invocation_ctr);

    const struct method_request_action *m =
        (const void *)a->plaintext;
    if (m->tag != 0xC3 || m->class_id != CLASS_ID_DISCONNECT_CTRL)
        return DLMS_WRONG_CLASS;
    if (memcmp(m->obis, OBIS_DISCONNECT_CTRL, 6))
        return DLMS_WRONG_OBIS;

    switch (m->method_id) {
    case 1:  return relay_drive_open();    /* DISCONNECT */
    case 2:  return relay_drive_close();   /* RECONNECT  */
    default: return DLMS_BAD_METHOD;
    }
}

/* =========================================================
 *  Firmware image verification (IEC 62056-5-3 §8.7.1.4).
 *  Image Transfer class (IC 18) stages firmware; activation
 *  gate is again RSA-PSS against UTILITY_BACKOFFICE_PUB
 *  (in most deployments; some OEMs use a separate FW key).
 * ========================================================= */

struct fw_manifest {
    char      meter_model[24];
    uint32_t  fw_version;
    uint32_t  min_downgrade_version;
    uint8_t   image_sha256[32];
    uint32_t  not_before;
    uint32_t  not_after;
    uint8_t   sig[256];
};

/* ---- What breaks when UTILITY_BACKOFFICE_PUB is factored --
 * - Fleet-scale disconnect: tens of millions of premises
 *   cut simultaneously. ERCOT-scale grid destabilization;
 *   NERC CIP reportable event.
 * - Firmware override: load attacker's firmware to meters,
 *   persist, disable remote-disconnect safeguards, forge
 *   billing data.
 * - Replay-window abuse: invocation_ctr is monotonic per
 *   meter, not per key, so one valid factored-key forgery
 *   against each meter advances that meter's counter and
 *   locks out the legitimate utility until reprovisioning.
 * --------------------------------------------------------- */
