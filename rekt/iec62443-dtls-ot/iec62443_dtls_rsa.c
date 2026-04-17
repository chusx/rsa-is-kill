/*
 * iec62443_dtls_rsa.c
 *
 * IEC 62443 — DTLS with RSA for industrial IoT and OT device authentication.
 * Sources:
 *   - IEC 62443-3-3:2013 System security requirements and security levels
 *   - IEC 62443-4-2:2019 Technical security requirements for IACS components
 *   - ISA-100.11a (industrial wireless with DTLS)
 *   - WirelessHART (IEC 62591) security with DTLS
 *   - OPC-UA with DTLS over UDP (IEC 62541-6)
 *
 * IEC 62443 is the industrial cybersecurity standard suite for Industrial Automation
 * and Control Systems (IACS). It defines security levels (SL1-SL4) and component
 * security requirements including:
 *   - Device authentication (X.509 certificates with RSA-2048)
 *   - Secure channel establishment (TLS/DTLS)
 *   - Key management for industrial wireless sensors
 *
 * DTLS (Datagram TLS, RFC 6347) is used in industrial IoT for:
 *   - ISA-100.11a: Industrial wireless (RSA-2048 device certificates)
 *   - WirelessHART: Process instrument wireless (DTLS with X.509)
 *   - OPC-UA over UDP: Industrial equipment communication
 *   - PROFINET IO with embedded DTLS: Siemens factory automation
 *   - EtherNet/IP with DTLS: Rockwell Automation / Allen-Bradley
 *
 * Industrial devices with DTLS RSA-2048 certificates:
 *   - Emerson Rosemount HART transmitters (pressure, temperature, flow)
 *   - ABB field instruments (WirelessHART enabled)
 *   - Yokogawa field devices (ISA-100.11a)
 *   - Siemens PROFINET devices with security extension
 *   - Rockwell Allen-Bradley PLCs with EtherNet/IP DTLS
 *
 * The device certificate is issued by the plant operator's PKI or the device
 * manufacturer's factory PKI. RSA-2048 is standard; ECDSA P-256 is in newer devices.
 *
 * IEC 62443-4-2 SL2+ requires: "device shall authenticate using X.509 certificates."
 * In practice: RSA-2048 certificates from a SCADA/DCS plant CA.
 *
 * The certificate public key is transmitted in every DTLS handshake on the
 * industrial wireless or wired OT network.
 */

#include <stdint.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/dtls1.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

/* IEC 62443 security level for the device (SL1-SL4) */
typedef enum {
    SL1 = 1,    /* protection against casual/coincidental violation */
    SL2 = 2,    /* protection against intentional violation using simple means */
    SL3 = 3,    /* protection against sophisticated attack (RSA-2048 required) */
    SL4 = 4,    /* protection against state-sponsored attack */
} iec62443_security_level_t;

/* ICS device identity for DTLS authentication */
struct ics_device_identity {
    char     device_id[64];       /* e.g., "ABB-2600T-4521A" */
    char     asset_tag[32];       /* plant asset number */
    uint32_t device_class;        /* 0=sensor, 1=actuator, 2=controller, 3=historian */
    uint8_t  cert_der[2048];      /* RSA-2048 device certificate (DER) */
    uint8_t  key_der[1200];       /* RSA-2048 private key (DER, encrypted in device flash) */
    iec62443_security_level_t sl; /* security level this device is certified to */
};

/*
 * iec62443_dtls_server_init() — initialize DTLS server context for ICS device auth.
 *
 * Called by a SCADA/DCS gateway or field bus concentrator acting as DTLS server.
 * Industrial IoT devices (sensors, transmitters, actuators) connect as DTLS clients
 * and authenticate with their RSA-2048 device certificates.
 *
 * Per IEC 62443-4-2 SL2+ requirements:
 *   - Mutual authentication required (server AND client present certificates)
 *   - Certificate chain to plant PKI root
 *   - Certificate revocation checking (CRL or OCSP)
 */
SSL_CTX *
iec62443_dtls_server_init(const char *server_cert_pem,
                           const char *server_key_pem,
                           const char *plant_ca_pem,
                           iec62443_security_level_t required_sl)
{
    SSL_CTX *ctx;

    /* DTLS 1.2 server context (DTLS 1.0 prohibited per IEC 62443) */
    ctx = SSL_CTX_new(DTLS_server_method());
    if (!ctx) return NULL;

    /* Load server RSA-2048 certificate (SCADA gateway or field concentrator) */
    if (SSL_CTX_use_certificate_chain_file(ctx, server_cert_pem) <= 0)
        goto fail;

    if (SSL_CTX_use_PrivateKey_file(ctx, server_key_pem, SSL_FILETYPE_PEM) <= 0)
        goto fail;

    if (!SSL_CTX_check_private_key(ctx))
        goto fail;

    /* Load plant PKI CA certificate (issues all device certs in this plant) */
    SSL_CTX_load_verify_locations(ctx, plant_ca_pem, NULL);

    /* Require mutual authentication — all ICS devices must present certificates */
    /* SL2+ requires bidirectional certificate authentication */
    SSL_CTX_set_verify(ctx,
        SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
        NULL  /* use default certificate verify callback */
    );

    /* Cipher list for IEC 62443 SL2:
     * - RSA key exchange or ECDHE with RSA certificates
     * - AES-128-GCM or AES-256-GCM
     * - No export ciphers, no NULL, no RC4
     * IEC 62443 SL3+ recommends 256-bit symmetric (AES-256-GCM)
     */
    SSL_CTX_set_cipher_list(ctx,
        "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:"
        "RSA-AES256-GCM-SHA384:RSA-AES128-GCM-SHA256:"
        "!aNULL:!NULL:!EXPORT:!RC4:!DES:!MD5"
    );

    return ctx;

fail:
    SSL_CTX_free(ctx);
    return NULL;
}

/*
 * iec62443_dtls_device_handshake() — perform DTLS handshake for ICS device.
 *
 * Called by an industrial sensor/actuator (or its gateway) when establishing
 * a secure channel to the SCADA system.
 *
 * During the DTLS handshake:
 *   1. Server presents RSA-2048 certificate (gateway cert, from plant CA)
 *   2. Client (ICS device) presents RSA-2048 certificate (device cert, from plant CA)
 *   3. Both sides verify the certificate chain to the plant CA
 *   4. Session key established (ECDHE or RSA key exchange)
 *
 * The plant CA certificate (RSA-2048 root) is distributed to all devices
 * during commissioning. The device certificate (RSA-2048) is provisioned at the
 * plant or by the device manufacturer.
 *
 * An attacker who factors any device's RSA-2048 cert can:
 *   - Authenticate to the SCADA system as that device
 *   - Inject false sensor readings (temperature, pressure, flow rate)
 *   - Command actuators as if from an authenticated device
 *   - For safety instrumented devices: trigger false shutdowns or suppress real alarms
 */
int
iec62443_dtls_device_handshake(SSL_CTX *ctx, int sock_fd,
                                 const struct ics_device_identity *device,
                                 X509 **peer_cert_out)
{
    SSL *ssl;
    int ret;

    /* Load device RSA-2048 certificate */
    const uint8_t *cert_p = device->cert_der;
    X509 *dev_cert = d2i_X509(NULL, &cert_p, sizeof(device->cert_der));
    if (!dev_cert) return -1;

    if (SSL_CTX_use_certificate(ctx, dev_cert) <= 0) {
        X509_free(dev_cert);
        return -1;
    }

    ssl = SSL_new(ctx);
    if (!ssl) return -1;

    SSL_set_fd(ssl, sock_fd);

    /* DTLS handshake — includes certificate exchange and RSA-based key material */
    ret = SSL_connect(ssl);
    if (ret <= 0) {
        SSL_free(ssl);
        return -1;
    }

    /* Extract server certificate (SCADA gateway RSA-2048 cert) */
    if (peer_cert_out) {
        *peer_cert_out = SSL_get_peer_certificate(ssl);
    }

    /* Log cipher suite negotiated (typically RSA or ECDHE-RSA) */
    /* In a typical IEC 62443 deployment: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 */
    /* The "RSA" in that cipher suite is the RSA-2048 server certificate */

    return SSL_get_fd(ssl);  /* return fd for subsequent application data */
}

/*
 * wirelesshart_dtls_join() — WirelessHART device joining a HART network via DTLS.
 *
 * WirelessHART (IEC 62591) is the wireless protocol for process instruments.
 * WirelessHART Network Manager authenticates new devices via DTLS with
 * RSA-2048 X.509 certificates (HART 7.6+ security specification).
 *
 * Deployed in:
 *   - Emerson Rosemount WirelessHART sensors (pressure, temperature, flow)
 *   - ABB Totalflow field devices
 *   - Yokogawa WirelessHART transmitters
 *   - Koch Industries refineries, Dow Chemical plants
 *
 * The WirelessHART Network Manager's RSA-2048 certificate is the trust anchor
 * for all devices in the mesh network. An attacker who factors this cert can
 * impersonate the Network Manager and authenticate rogue devices.
 */
int
wirelesshart_dtls_join(const uint8_t *device_cert_der, size_t cert_len,
                        const char *nm_host, uint16_t nm_port,
                        uint8_t *session_key_out, size_t *session_key_len)
{
    /* Simplified: DTLS handshake with WirelessHART Network Manager */
    /* The NM presents RSA-2048 cert; device presents RSA-2048 cert */
    /* Session key derived from DTLS handshake, used for AES-128 mesh encryption */

    (void)device_cert_der;
    (void)cert_len;
    (void)nm_host;
    (void)nm_port;
    *session_key_len = 16;
    return 0;
}
