/* Source: FreeRADIUS/freeradius-server src/lib/eap/tls.c
 *         + src/modules/rlm_eap/types/rlm_eap_tls/rlm_eap_tls.c
 *
 * EAP-TLS (RFC 5216) is the authentication protocol for enterprise Wi-Fi
 * (WPA2-Enterprise / WPA3-Enterprise / 802.1X) and wired 802.1X network access.
 *
 * Every corporation, university, hospital, government building, and airport
 * using WPA2-Enterprise authenticates users and devices with X.509 certificates
 * over EAP-TLS. The client presents an RSA certificate; the RADIUS server
 * (FreeRADIUS, Cisco ISE, Aruba ClearPass, Microsoft NPS) validates it.
 *
 * FreeRADIUS is the dominant open-source RADIUS server — ~60% of RADIUS
 * deployments. It handles EAP-TLS, EAP-TTLS, and PEAP.
 *
 * The TLS handshake in EAP-TLS uses:
 *   - Server certificate: RSA-2048 or ECDSA-P256 (from RADIUS server CA)
 *   - Client certificate: RSA-2048 (default for most enterprise PKI)
 *   - Cipher suite negotiation: TLS_RSA_WITH_AES_256_CBC_SHA256 (common)
 *                               or ECDHE_RSA_WITH_AES_256_GCM_SHA384
 *
 * Both cipher suites require RSA certificates for the server.
 * No PQC cipher suite is defined in EAP-TLS (RFC 5216 / RFC 9190).
 */

/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2001 hereUgo Software */

#include <openssl/ssl.h>
#include <openssl/x509.h>

/* EAP-TLS over 802.1X: the TLS conversation is tunneled inside RADIUS
 * Access-Request/Access-Challenge packets.
 * Every frame is authenticated with RSA certificates.
 *
 * tls_session_new() — create a TLS context for an EAP-TLS supplicant.
 * @conf:       TLS configuration (certificate paths, CA, cipher list)
 * Returns:     TLS context ready for EAP-TLS handshake
 */
tls_session_t *tls_session_new(request_t *request, fr_tls_conf_t *conf,
                                int client_cert)   /* 1 = require client RSA cert */
{
    SSL_CTX *ctx = conf->ctx[0];   /* pre-built SSL context with RSA cert loaded */
    SSL     *ssl = SSL_new(ctx);

    if (client_cert) {
        /* Require client to present a certificate (mutual TLS) */
        SSL_set_verify(ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    }

    /* Cipher list — RSA-based suites are the default for enterprise Wi-Fi.
     * TLS 1.3 cipher suites (TLS_AES_256_GCM_SHA384) still use RSA for the
     * certificate authentication, just not for key exchange. */
    SSL_set_cipher_list(ssl, conf->cipher_list);  /* e.g., "ECDHE-RSA-AES256-GCM-SHA384" */

    return tls_session_alloc(request, conf, ssl, client_cert);
}

/*
 * 802.1X deployment scale:
 *   - Enterprise Wi-Fi: every Fortune 500, university, hospital, government
 *   - Network Access Control (NAC): Cisco ISE alone has 100M+ endpoints
 *   - Eduroam: the global academic roaming network used at 10,000+ institutions
 *     (800M+ authentications/year, all EAP-TLS with RSA certificates)
 *
 * Device certificate distribution for 802.1X:
 *   - Microsoft Intune / JAMF / SCCM push RSA-2048 device certs via SCEP
 *   - Android (Work Profile): RSA-2048 via MDM-enrolled device cert
 *   - iOS/macOS: RSA-2048 via MDM enrollment
 *   - Wi-Fi calling (IMS/EAP-AKA): telecom carrier 802.1X for VoWi-Fi
 *
 * Replacing RSA-2048 device certificates across an enterprise requires:
 *   - New PKI CA with PQC root (no enterprise CA supports PQC yet)
 *   - MDM-pushed certificate enrollment (requires MDM PQC support)
 *   - RADIUS server PQC support (FreeRADIUS, ISE, ClearPass — none support PQC)
 *   - Supplicant PQC support (Windows wpa_supplicant, iOS, Android — none)
 *
 * The entire 802.1X ecosystem must move simultaneously — a flag day problem.
 */
