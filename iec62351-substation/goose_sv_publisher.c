/*
 * goose_sv_publisher.c
 *
 * IEC 61850 GOOSE + Sampled Values publisher with IEC 62351-6 RSA
 * authentication extension. Runs inside IED firmware (SEL-751A,
 * GE UR T60, Siemens SIPROTEC 5 7UT87, ABB REF630) on every digital
 * substation worldwide. The RSA primitives are in `iec62351_rsa.c`;
 * this file is the multicast-publisher integration point.
 *
 * Deployment scale: every new-build transmission substation since
 * ~2015 (IEC 61850-9-2 process bus) runs GOOSE+SV over the station
 * LAN.  The IEC 62351-6 RSA option authenticates safety-critical
 * messages (trip commands, interlocks, current transformer merging
 * unit samples) to defend against the process-bus-injection attack
 * demonstrated in multiple academic papers and incidents.
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include "iec61850.h"
#include "iec62351.h"


struct ied_publisher {
    uint8_t   src_mac[6];
    uint16_t  goose_appid;
    uint32_t  sv_appid;
    uint8_t   rsa_priv_key_handle;      /* label into on-board HSM / TPM */
    uint8_t   cert_der[2048]; size_t cert_der_len;
    uint32_t  state_number;
    uint32_t  sequence_number;
};


/* Called on every status change of a protection relay data attribute
 * — breaker position, pickup flag, trip flag, lockout, interlock. */
int
goose_publish_status_change(struct ied_publisher *p,
                              const struct goose_payload *dsv)
{
    uint8_t frame[1500]; size_t n = 0;
    n += l2_encap_ether(frame, p->src_mac, ETH_GOOSE);
    n += goose_encode_apdu(frame + n, dsv,
                            p->state_number, p->sequence_number);

    /* IEC 62351-6 §7.3 extension: RSA-PSS-SHA256 signature over the
     * full GOOSE APDU.  Signature TLV appended as a PrivateASN.1
     * wrapper, verifiable by subscriber IEDs holding the publisher's
     * pinned cert.  On a typical SIPROTEC-class CPU, sign time is
     * ~2 ms — tight but feasible for the 1-20 ms GOOSE retransmit
     * cadence. */
    uint8_t sig[512]; size_t sig_len;
    if (iec62351_rsa_sign(p->rsa_priv_key_handle,
                           frame, n, sig, &sig_len) != 0)
        return -1;
    n += iec62351_append_signature_tlv(frame + n, sig, sig_len);

    l2_multicast_send(frame, n);

    p->state_number++;
    p->sequence_number = 0;
    return 0;
}


/* Sampled Values: 4 kHz or 12.8 kHz sampling of CT/VT secondaries;
 * digital substations replace copper wiring from CT/VT to relay.
 * IEC 62351 here signs a burst (typically 80 frames batched, per
 * 62351-9 performance class) so the bus overhead stays tractable. */
int
sv_publish_burst(struct ied_publisher *p, const struct sv_burst *b)
{
    uint8_t frame[9000]; size_t n = 0;
    n += l2_encap_ether(frame, p->src_mac, ETH_SV);
    n += sv_encode_asdu_burst(frame + n, b);

    uint8_t sig[512]; size_t sig_len;
    if (iec62351_rsa_sign(p->rsa_priv_key_handle,
                           frame, n, sig, &sig_len) != 0)
        return -1;
    n += iec62351_append_signature_tlv(frame + n, sig, sig_len);
    l2_multicast_send(frame, n);
    return 0;
}


/* Breakage:
 * An RSA factoring attack on a substation's Station CA lets the
 * attacker mint IED certs and publish forged GOOSE trip commands
 * that peer IEDs verify-and-act-upon within one 61850 cycle
 * (~4 ms). This is exactly the primitive used in the 2015/2016
 * Ukraine grid attacks conceptually — factor-hence-sign turns that
 * into an operational capability against any utility that has
 * standardized on IEC 62351-6 RSA authentication. */
