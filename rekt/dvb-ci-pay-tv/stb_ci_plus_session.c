/*
 * stb_ci_plus_session.c
 *
 * DVB CI+ v1.4 host-side (Set-Top-Box / integrated TV) session stack.
 * The Authenticated Key Exchange (AKE) RSA primitives are in
 * `dvb_ci_ake.c`; this file is the integration point inside the host
 * firmware: CICAM insertion detection, application-level protocol
 * (CA_PMT, CC SAC, Content Control Resource), and the per-event URI
 * / copy-control state pushed down the authenticated pipe to the
 * demux.
 *
 * Deployed in: Samsung/LG/Sony/Panasonic smart TVs (integrated CI+
 * slot), STB platforms from Sagemcom, Humax, Technicolor, Kaon, and
 * the CAM side of Conax, Irdeto, Nagravision, Viaccess-Orca,
 * CryptoGuard. European pay-TV operators (Sky, Canal+, Movistar+,
 * HD+, Tivù, Digi) distribute CICAMs that terminate this session.
 */

#include <stdint.h>
#include "dvb_ci.h"
#include "dvb_ci_plus_root.h"


struct ci_plus_session {
    uint8_t  cam_device_cert_der[2048]; size_t cam_device_cert_len;
    uint8_t  cam_brand_cert_der [2048]; size_t cam_brand_cert_len;
    uint8_t  host_device_cert_der[2048]; size_t host_device_cert_len;
    uint8_t  host_brand_cert_der [2048]; size_t host_brand_cert_len;

    /* Derived at end of AKE */
    uint8_t  sek[16];                   /* SAC encryption key */
    uint8_t  sak[16];                   /* SAC auth key       */
    uint32_t ake_epoch;
};


/* Invoked as soon as the PCMCIA / USB-CI CAM handshake reports
 * Resource Manager has opened on the transport layer. */
int
ci_plus_bring_up(struct ci_plus_session *s)
{
    /* 1.  Exchange device + brand certs.  CI+ LLP roots live in
     *     silicon / secure storage; brand certs are issued by Sony
     *     DADC Austria AG (the CI+ LLP operator) under their RSA-2048
     *     root. */
    if (ci_rx_device_cert(s) || ci_rx_brand_cert(s))       return -1;
    if (ci_tx_device_cert(s) || ci_tx_brand_cert(s))       return -1;

    /* 2.  Validate chain: device ← brand ← CI+ LLP root.  Fail here
     *     means the CAM is refused — classic "this CAM is not
     *     licensed for your host" dialog. */
    if (ci_plus_verify_chain(
            s->cam_device_cert_der, s->cam_device_cert_len,
            s->cam_brand_cert_der , s->cam_brand_cert_len,
            ci_plus_llp_root_der) != 0)
        return -1;

    /* 3.  AKE (RSA-based mutual auth) + DH-1024 for a transport key,
     *     which is then used to derive SEK + SAK for the Secure
     *     Authenticated Channel (SAC). */
    if (ci_plus_run_ake(s) != 0) return -1;
    if (ci_plus_derive_sac_keys(s) != 0) return -1;

    /* 4.  Content Control Resource opens. CICAM now asserts URI
     *     (Usage Rules Information) bits per service — copy-never,
     *     copy-once, retention flag, EMI, APS, CGMS-A — on each
     *     CA_PMT descrambling session. The STB is obliged to enforce
     *     them on SPDIF / HDMI / analog legacy outputs. */
    ci_open_content_control(s);

    /* 5.  Authenticated PIN (parental / PPV): CAM prompts the STB,
     *     response is MAC'd under SAK through the SAC.  Same for
     *     host-initiated operator-message queries. */
    return 0;
}


/* URI bits reach the demux driver through a kernel ioctl, and the
 * HDMI TX driver consults them to gate HDCP output level. */
void
ci_plus_on_uri_update(struct ci_plus_session *s, const uint8_t *uri, size_t n)
{
    uint8_t plaintext[64];
    if (ci_sac_decrypt(s->sek, s->sak, uri, n, plaintext) != 0) return;
    demux_set_uri(plaintext);
    hdmi_tx_set_output_protection(plaintext[0] & 0x03);
}


/* Breakage model: a factoring attack on the CI+ LLP root lets an
 * attacker mint "licensed" CAM and Host certs, so (a) unlicensed
 * pirate CAMs descramble operator services without revocation risk;
 * (b) "host emulator" boxes convince Nagravision/Conax CAMs they're
 * talking to a compliant TV while actually streaming the cleartext
 * MPEG-TS out over IP, collapsing the copy-protection model that
 * European pay-TV (and, via CI+ integration on HbbTV devices,
 * terrestrial FTA premium content) relies on. */
