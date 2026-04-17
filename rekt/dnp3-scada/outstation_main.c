/*
 * outstation_main.c
 *
 * DNP3 outstation (RTU / IED) main loop with IEEE 1815-2012 Secure
 * Authentication v5 wrapped around every application-layer message.
 * Deployed in substation RTUs (SEL-3530, GE Multilin D60, ABB RTU540,
 * Siemens SICAM A8000), wellhead SCADA, water/wastewater PLCs, and
 * pipeline compressor-station controls across every major North
 * American utility and ISO (PJM, ERCOT, MISO, CAISO, AESO, IESO).
 *
 * The RSA primitives driving asymmetric key update live in
 * `dnp3_sav5_rsa_auth.c`. This file shows the polling/control-sequence
 * integration point.
 */

#include <stdint.h>
#include <stdio.h>
#include "dnp3_sav5.h"
#include "opendnp3_outstation.h"


/* Persistent security state — pre-shared Update Key, per-user session
 * keys (K_CM + K_CM_MAC), running challenge counter, last RSA-
 * authenticated key-change timestamp. Stored in the RTU's battery-
 * backed NVRAM alongside the point database. */
static struct dnp3_sav5_state g_sec;

/* Per-user Update-Key records.  Updated via the asymmetric update
 * procedure — Authority (utility SCADA master) signs under its RSA
 * private key; RTU verifies against the pinned Authority cert. */
struct dnp3_user {
    uint16_t user_number;
    char     user_name[32];
    uint8_t  update_key[32];        /* AES-256 wrapped Update Key */
    uint8_t  authority_cert_der[2048];
    size_t   authority_cert_len;
};
static struct dnp3_user g_users[DNP3_MAX_USERS];


/* ---- message path: every g.var.12.1 application data object
 *      received on TCP/20000 or serial is dispatched here ---- */
int
dnp3_outstation_on_app_message(const uint8_t *apdu, size_t len)
{
    /* 1.  SAv5 critical-ASDU detection: CROB (g12v1), AO (g41),
     *     cold/warm restart, enable/disable unsolicited, file I/O. */
    if (!dnp3_sav5_is_critical(apdu, len)) {
        return opendnp3_dispatch(apdu, len);      /* non-critical → direct */
    }

    /* 2.  Challenge-response per IEEE 1815-2012 §7.5.2.  MAC is
     *     HMAC-SHA256 keyed by the current session K_CM_MAC. */
    uint8_t challenge[16];
    dnp3_sav5_emit_challenge(&g_sec, challenge);

    uint8_t reply[256]; size_t reply_len;
    if (dnp3_sav5_await_reply(&g_sec, challenge, reply, &reply_len) != 0)
        return dnp3_sav5_report("aggressive-mode-auth-fail"), -1;

    if (dnp3_sav5_verify_mac(&g_sec, reply, reply_len) != 0)
        return dnp3_sav5_report("mac-mismatch"), -1;

    /* 3.  Key-change watchdog.  When the session-key TTL expires or
     *     the master rotates the Update Key, an RSA-signed Key Change
     *     Object (g120v8) arrives.  That path is in
     *     dnp3_sav5_rsa_auth.c::dnp3_sav5_process_key_change(). */
    if (dnp3_sav5_keychange_pending(&g_sec)) {
        if (dnp3_sav5_process_key_change(&g_sec, g_users) != 0) {
            dnp3_sav5_report("key-change-rsa-verify-fail");
            return -1;    /* RTU stays on prior keys; master retries */
        }
    }

    /* 4.  Hand authenticated ASDU down to the opendnp3 outstation
     *     (point execution, select-before-operate, etc.). */
    return opendnp3_dispatch(apdu, len);
}


/* ---- boot-time provisioning: the RTU is commissioned with an
 *      operator-signed Authority cert + initial Update Keys flashed
 *      via the commissioning laptop over the engineering port ---- */
int
dnp3_outstation_boot(void)
{
    if (nvram_load(&g_sec, g_users) != 0) {
        fprintf(stderr, "first-boot provisioning required\n");
        return -1;
    }
    opendnp3_bind(DNP3_TCP_PORT, dnp3_outstation_on_app_message);
    printf("DNP3 outstation up, SAv5 enforced on critical ASDUs\n");
    return 0;
}


/* A factoring break on utility Authority CAs lets an attacker forge
 * Key Change messages at will — rotating outstations onto attacker-
 * controlled Update Keys, after which every CROB and analog-output
 * command the attacker issues passes SAv5 authentication. The same
 * attack extended across a balancing authority's RTU population is
 * an Aurora-style trip/reclose or generator-damage primitive
 * delivered at grid scale. */
