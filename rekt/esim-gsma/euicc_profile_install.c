/*
 * euicc_profile_install.c
 *
 * GSMA SGP.22 eSIM Remote SIM Provisioning: SM-DP+ to eUICC
 * profile installation flow. The eUICC (embedded SIM) on every
 * modern smartphone and IoT module carries an RSA-2048 eUICC
 * certificate issued by the GSMA CI (Certificate Issuer, G+D /
 * Thales). The SM-DP+ (Subscription Manager Data Preparation+)
 * authenticates to the eUICC via RSA mutual auth before pushing
 * a Bound Profile Package (BPP) — the IMSI, Ki, OPc, and AKA
 * credentials that bind the device to an operator.
 *
 * A factored CI root yields the ability to impersonate any
 * SM-DP+ to any eUICC, or any eUICC to any SM-DP+.
 */

#include <stdint.h>
#include <string.h>
#include "sgp22.h"

extern const uint8_t GSMA_CI_ROOT_PUB[384];      /* RSA-3072     */

/* ES9+ (SM-DP+ to LPA) initiateAuthentication response, as
 * delivered to the Local Profile Assistant on the device. */
struct auth_server_response {
    uint8_t   txn_id[16];
    uint8_t   server_cert[2048]; size_t server_cert_len;
    uint8_t   server_signed1[256];     /* serverSigned1           */
    uint8_t   server_sig1[384];        /* RSA-PSS over signed1    */
    uint8_t   euicc_ci_pkid[32];       /* identifies CI root      */
};

/* ES10b (LPA to eUICC) authenticateServer: the eUICC verifies
 * the SM-DP+ certificate chain against its embedded CI root,
 * then produces its own signed response (euiccSigned1). */
struct euicc_auth_response {
    uint8_t   euicc_cert[2048]; size_t euicc_cert_len;
    uint8_t   euicc_signed1[256];
    uint8_t   euicc_sig1[384];
};

int euicc_authenticate_server(const struct auth_server_response *srv,
                              struct euicc_auth_response *out)
{
    /* Chain server cert to GSMA CI root embedded in eUICC ISD-R. */
    if (x509_chain_verify(srv->server_cert, srv->server_cert_len,
            GSMA_CI_ROOT_PUB, sizeof GSMA_CI_ROOT_PUB))
        return SGP_AUTH_FAIL;

    /* Verify serverSigned1 under server cert. */
    uint8_t h[32];
    sha256(srv->server_signed1, 256, h);
    if (verify_with_cert(srv->server_cert, srv->server_cert_len,
                         h, srv->server_sig1, sizeof srv->server_sig1))
        return SGP_SIG_FAIL;

    /* Produce euiccSigned1 (containing serverChallenge echo,
     * EID, eUICC info). Sign with eUICC private key. */
    euicc_build_signed1(srv, out->euicc_signed1);
    sha256(out->euicc_signed1, 256, h);
    euicc_rsa_sign(h, 32, out->euicc_sig1, sizeof out->euicc_sig1);
    memcpy(out->euicc_cert, euicc_get_cert(), euicc_cert_len());
    out->euicc_cert_len = euicc_cert_len();
    return SGP_OK;
}

/* =========================================================
 *  Profile installation: after mutual auth, SM-DP+ pushes a
 *  Bound Profile Package (BPP). The BPP is encrypted under
 *  a session key derived from the mutual-auth handshake (SCP03t
 *  key agreement with RSA key transport). Inside the BPP:
 *    - IMSI, Ki, OPc (AKA credentials)
 *    - USIM, ISIM applets (JavaCard CAP)
 *    - Operator branding, APN, MMS config
 * ========================================================= */

struct bound_profile_package {
    uint8_t   profile_metadata[256];
    uint8_t   encrypted_profile[32768];
    size_t    encrypted_len;
    uint8_t   mac[16];                 /* AES-CMAC, SCP03t key   */
};

/* ---- Attack scenarios -------------------------------------
 *  GSMA CI root factored:
 *    * Impersonate any SM-DP+ to any eUICC: install a rogue
 *      profile with attacker-chosen Ki/OPc. The device now
 *      authenticates to a rogue core network. All calls, SMS,
 *      data are intercepted. ~3 billion eSIM-capable devices.
 *    * Impersonate any eUICC to SM-DP+: request a legitimate
 *      profile for any subscriber, stealing their identity.
 *    * Clone an existing subscriber's profile onto an attacker
 *      device for passive or active interception.
 *
 *  eUICC device cert factored (per-device):
 *    Lower blast radius (one device), but allows profile
 *    extraction from that device's ISD-R without physical
 *    access — remote SIM cloning.
 *
 *  Recovery: GSMA CI re-key + every eUICC on earth needs a
 *  new trust anchor. For devices that cannot OTA-update the
 *  ISD-R (most current generation), this is a silicon-refresh
 *  event measured in handset-replacement cycles (3-5 years).
 * --------------------------------------------------------- */
