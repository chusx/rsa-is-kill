/*
 * plc_field_device_comms.c
 *
 * IEC 62443-3-3 / ISA/IEC 62443-4-2 compliant DTLS comms from a PLC or
 * DCS controller to field devices — the OT-side network stack that
 * talks to flow transmitters, valve positioners, VFDs, and smart
 * sensors.  The DTLS RSA handshake primitives live in
 * `iec62443_dtls_rsa.c`; this file is the industrial-control
 * integration point (ISR / watchdog / fail-safe behavior).
 *
 * Deployed on: Siemens S7-1500, Rockwell ControlLogix/CompactLogix,
 * Schneider M580/M580S (safety), Emerson DeltaV ProPlus, Honeywell
 * Experion PKS C300, ABB AC800M, Yokogawa CENTUM VP CP451. Covers
 * oil & gas (Aramco, Shell, Equinor), chemical plants (BASF, Dow),
 * power generation (Vattenfall, Duke Energy), water treatment, and
 * pharma manufacturing.  IEC 62443-3-3 SL-2+ mandates mutual authN
 * on OT flows above Zone/Conduit boundaries; most operators use
 * RSA-2048 X.509 under an OT-internal CA (Siemens TIA PKI, Claroty
 * xDome CA, Nozomi Arc CA).
 */

#include <stdint.h>
#include "plc_rt.h"
#include "iec62443_dtls.h"


struct field_session {
    uint32_t     device_id;
    const char  *device_tag;        /* e.g. "FT-102-FLOW-XMT" */
    dtls_ctx_t  *dtls;
    uint64_t     last_rx_us;
    uint64_t     watchdog_us;
};


/* Scan-cycle callback: PLC scan runs at 10-100 ms, depending on
 * application (process control ~100 ms, fast motion ~1 ms). */
void
plc_scan_cycle_comms(struct field_session *fs)
{
    /* Renegotiate DTLS if handshake age exceeds site policy
     * (typical: 8 hours, config-driven). Renegotiation is triggered
     * at low OT load to avoid transient safety-signal drop. */
    if (dtls_session_age(fs->dtls) > SITE_DTLS_REKEY_SEC &&
        plc_rt_state() == PLC_STATE_STABLE) {
        iec62443_dtls_rekey(fs->dtls);    /* full RSA handshake */
    }

    /* Pull any pending application PDU. */
    uint8_t buf[1400]; ssize_t n = dtls_recv(fs->dtls, buf, sizeof buf);
    if (n > 0) {
        fs->last_rx_us = rt_clock_us();
        app_dispatch_field_pdu(fs->device_id, buf, n);
    }

    /* Safety watchdog: if we haven't received anything for 500 ms
     * and the device is in our safety chain (SIL-2+), force the
     * actuator into the configured fail-safe position. */
    if (rt_clock_us() - fs->last_rx_us > fs->watchdog_us) {
        safety_force_failsafe(fs->device_id);
        audit_log("comm_loss", fs->device_tag,
                  "DTLS heartbeat timeout — failsafe asserted");
    }
}


int
plc_field_bring_up(struct field_session *fs, const char *host,
                    uint16_t port, const struct iec62443_creds *creds)
{
    fs->dtls = iec62443_dtls_connect(host, port, creds);
    if (!fs->dtls) return -1;

    /* Pin device cert against the site's OT Issuing CA.  Cert
     * contains a deviceRole OID (ISA-95 hierarchy level), a
     * safetyIntegrityLevel OID (SIL-1..4), and a per-asset UUID
     * that ties to the CMDB / asset-inventory. */
    if (iec62443_verify_peer_role_sil(
            fs->dtls, "field_device", /* min_sil */ 2) != 0) {
        iec62443_dtls_close(fs->dtls);
        return -1;
    }

    fs->watchdog_us = 500 * 1000;     /* 500 ms */
    return 0;
}


/* Breakage:
 * An RSA factoring attack on a plant's OT Issuing CA lets an attacker
 * mint field-device certs and (a) stream falsified process values
 * that the PLC accepts as authentic — e.g., reporting tank level =
 * nominal when it's actually overflowing, mirroring the Trisis /
 * Stuxnet "PV spoofing" playbook; (b) flip the role OID to mint
 * controller certs that downstream HMIs accept, pivoting from field
 * read-only into supervisory write. Unlike IT TLS, OT DTLS
 * connections run for months between handshakes; a factoring break
 * silently persists until the next scheduled rekey. */
