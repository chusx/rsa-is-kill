/*
 * pnc_contract_cert.c
 *
 * ISO 15118-2 / -20 Plug-and-Charge (PnC) contract certificate
 * installation and TLS mutual auth between the EV (Electric
 * Vehicle) and the EVSE (charging station). The V2G Root CA is
 * RSA-2048 (transitioning to ECDSA in ISO 15118-20, but the
 * installed base is -2 with RSA for years).
 *
 * Chain: V2G Root CA -> MO Sub-CA (Mobility Operator) -> OEM
 * Provisioning Cert (installed at factory) or Contract Cert
 * (installed via CPS / Certificate Provisioning Service).
 *
 * A factored V2G Root or MO Sub-CA yields the ability to
 * impersonate any EV to any EVSE (free charging, grid abuse)
 * or any EVSE to any EV (MitM for billing fraud, or to inject
 * malicious firmware via ISO 15118-20 Vehicle-to-Grid update).
 */

#include <stdint.h>
#include <string.h>
#include "iso15118.h"

extern const uint8_t V2G_ROOT_PUB[384];

struct contract_cert_install_req {
    uint8_t   oem_prov_cert[2048]; size_t oem_prov_cert_len;
    uint8_t   dh_pub_key[256];         /* ECDH or RSA key transport */
    uint8_t   sig[384];                /* RSA-SHA256 over DH pub    */
};

struct contract_cert_install_resp {
    uint8_t   contract_cert[2048]; size_t contract_cert_len;
    uint8_t   encrypted_priv_key[256]; /* RSA-OAEP wrapped         */
    uint8_t   emaid[20];               /* e-Mobility Account ID    */
    uint8_t   cps_sig[384];
};

/* SECC (Supply Equipment Communication Controller) verifies
 * the EV's contract cert during TLS ClientCertificate. */
int secc_verify_ev_contract(const uint8_t *ev_cert, size_t cert_len)
{
    if (x509_chain_verify(ev_cert, cert_len,
            V2G_ROOT_PUB, sizeof V2G_ROOT_PUB))
        return V2G_CHAIN_FAIL;

    /* Extract EMAID from cert SAN — this is the billing identity. */
    char emaid[20];
    if (cert_extract_emaid(ev_cert, cert_len, emaid))
        return V2G_NO_EMAID;

    /* OCSP staple check against MO backend. */
    if (ocsp_check(ev_cert, cert_len)) return V2G_REVOKED;
    return V2G_OK;
}

/* After TLS auth, the SECC and EVCC negotiate a charging
 * session via V2GTP messages. The signed metering receipt
 * is the billing artefact — Eichrecht-relevant in the EU. */
struct metering_receipt {
    char       emaid[20];
    char       evse_id[20];
    uint64_t   start_ts;
    uint64_t   end_ts;
    uint32_t   energy_wh;
    float      max_power_kw;
    uint8_t    secc_cert[2048]; size_t secc_cert_len;
    uint8_t    sig[384];
};

/* ---- Grid-scale attack surface ----------------------------
 *  V2G Root factored:
 *    * Forge EV contract certs: unlimited free DC fast charging
 *      billed to arbitrary EMAIDs. Also: mass simultaneous
 *      15 kW-350 kW draw from forged EVs = localized grid
 *      overload at commercial charging hubs.
 *    * Forge EVSE certs: MitM the TLS session, inject modified
 *      charging schedules. Under ISO 15118-20 V2G bidirectional,
 *      command vehicles to discharge simultaneously = reverse
 *      power flow -> distribution transformer overload.
 *    * Forge CPS (Certificate Provisioning Service): install
 *      attacker-controlled contract certs into vehicle HSMs
 *      at the factory. Supply-chain compromise at OEM scale.
 *
 *  Recovery: Hubject / CATENA-X V2G PKI re-key; every EVSE and
 *  every EV needs new trust store. OTA for EVs (Tesla, VW) is
 *  plausible; non-OTA vehicles need dealer visit. Chargers need
 *  CPO (Charge Point Operator) truck-roll.
 * --------------------------------------------------------- */
