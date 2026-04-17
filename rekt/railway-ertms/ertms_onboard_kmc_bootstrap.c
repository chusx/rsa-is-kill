/*
 * ertms_onboard_kmc_bootstrap.c
 *
 * ERTMS/ETCS (European Train Control System) onboard EVC (European
 * Vital Computer) key management bootstrap. Wraps the RSA-based
 * TRANSPORT protection of KMAC (K-MAC authentication keys) defined
 * in SUBSET-137 + SUBSET-038, and the online KMC (Key Management
 * Centre) enrolment flow. RSA primitives are in
 * `ertms_x509_certificates.c`.
 *
 * Every ETCS Level 2 / Level 3 trackside + onboard in Europe + Morocco
 * + Saudi Arabia + Taiwan runs this stack: Thales, Alstom, Siemens
 * Mobility, Hitachi Rail (former Ansaldo STS), Bombardier (now part
 * of Alstom), CAF Signalling. KMC nodes are operated by each
 * national rail infrastructure manager (SNCF Réseau, DB InfraGO,
 * Infrabel, NS-ProRail, RFI, ADIF, Banedanmark, Network Rail,
 * Trafikverket, ÖBB Infrastruktur).
 *
 * SUBSET-137 v4.0.0 (2023) introduces the online-KMS flow this
 * file orchestrates; SUBSET-114 covers the classical offline KMAC
 * distribution for legacy Class B fallback.
 */

#include <stdint.h>
#include <string.h>
#include "ertms_kmc.h"
#include "ertms_x509_certificates.h"


struct evc_identity {
    char etcs_id[14];         /* 24-bit ETCS-ID + 24-bit NID_C + 56-bit NID_ENGINE */
    uint8_t evc_cert_der[2048]; size_t evc_cert_len;     /* RSA-2048 EVC leaf */
    uint8_t evc_priv_handle;  /* opaque reference into onboard HSM */
    uint8_t root_ca_der[2048];  size_t root_ca_len;      /* ERA-trusted Root CA */
};


/* Boot-time bring-up of the ETCS authentication context. Runs every
 * time the EVC powers up (driver turns key; or following reset after
 * fault). */
int
evc_kmc_bootstrap(struct evc_identity *evc,
                   const char *kmc_hostname /* e.g. kmc.snr.sncf.fr */)
{
    /* 1. TLS 1.2+ connect to the KMC. RFC 7925 profile per SUBSET-137.
     *    Mutual auth: EVC presents its X.509 RSA-2048 cert; KMC
     *    presents its own RSA-2048 cert. Both chain to an ERA-
     *    approved root (a Notifying Body signs the IM root; the IMs
     *    cross-sign as part of ERTMS Baseline 3 Release 2 / Baseline
     *    4). */
    ertms_tls_ctx_t *tls = ertms_tls_connect_mutual(
        kmc_hostname, ERTMS_KMC_TCP_PORT,
        evc->evc_cert_der, evc->evc_cert_len,
        evc->evc_priv_handle,
        evc->root_ca_der, evc->root_ca_len);
    if (!tls) return ERTMS_KM_TLS_FAIL;

    /* 2. KMS_Req (Key Management Service request) — EVC announces
     *    its ETCS_ID + firmware version + currently-held KMAC key
     *    generation IDs. */
    if (ertms_kms_send_request(tls, evc) != 0)
        return ERTMS_KM_PROTO_FAIL;

    /* 3. KMS_Response — KMC returns a set of K_TRANS-wrapped KMAC
     *    keys, one per RBC (Radio Block Centre) the train is likely
     *    to encounter on its route. Each wrapped KMAC is 24 bytes
     *    (128-bit KMAC + metadata), encrypted under the EVC's RSA
     *    pubkey using RSA-OAEP, and MAC'd by the KMC's signing key. */
    struct kms_response resp;
    if (ertms_kms_recv_response(tls, &resp) != 0)
        return ERTMS_KM_PROTO_FAIL;

    /* 4. Unwrap each KMAC via onboard HSM. RSA-OAEP decrypt on the
     *    EVC's private key. This is the primitive that collapses
     *    under a factoring attack. */
    for (size_t i = 0; i < resp.n_kmac_records; i++) {
        uint8_t kmac[16];
        if (ertms_rsa_oaep_unwrap_kmac(
                evc->evc_priv_handle,
                resp.kmac_records[i].wrapped_kmac,
                resp.kmac_records[i].wrapped_kmac_len,
                kmac, sizeof kmac) != 0)
            return ERTMS_KM_UNWRAP_FAIL;

        ertms_hsm_install_kmac(resp.kmac_records[i].rbc_id,
                                resp.kmac_records[i].kmac_id,
                                kmac);
    }

    /* 5. Confirm install, close TLS. EVC now has KMACs ready for
     *    any RBC it meets en route; each RBC handshake uses the
     *    KMAC-keyed AES-CBC-MAC (Eurobalise ETCS application layer)
     *    to authenticate movement authorities. */
    ertms_tls_close(tls);
    return 0;
}


/* ---- Breakage ----
 *
 * The movement authorities that tell an ETCS train how far it may
 * proceed and at what speed are MAC-authenticated by KMACs
 * distributed via the flow above, which is itself protected by
 * RSA-2048 cert-based TLS + RSA-OAEP KMAC wrapping.
 *
 * A factoring attack against the ERA-approved ETCS Root CAs lets an
 * attacker mint a fake KMC cert, have every EVC on the network
 * unwittingly enroll against it, and issue arbitrary KMACs that
 * subsequently MAC forged movement authorities. Operational blast
 * radius: fraudulent "proceed to 160 km/h into a blocked track"
 * messages delivered with a valid KMAC on the Eurobalise channel,
 * which the EVC is required by the safety case to obey. This is why
 * ERA Technical Opinion ERA-OPI-2023-01 calls out post-quantum
 * migration of ETCS PKI as a 2030-timeline priority for the European
 * railway network.
 */
