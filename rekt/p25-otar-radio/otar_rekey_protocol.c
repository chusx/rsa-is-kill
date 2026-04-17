/*
 * otar_rekey_protocol.c
 *
 * APCO P25 Over-The-Air Rekeying (OTAR) protocol. P25 Phase II
 * radios (Motorola APX, Harris XL, Kenwood NX-5000) use OTAR
 * to distribute Traffic Encryption Keys (TEKs) and Key
 * Encryption Keys (KEKs) from the KMF (Key Management Facility)
 * to subscriber radios over the air.
 *
 * The OTAR protocol wraps the new TEK/KEK under the radio's
 * RSA public key (RSA-2048, stored in the radio's crypto
 * module). The KMF cert chains to the agency root CA (FBI CJIS,
 * state DPS, metro PD). A factored agency root allows an
 * attacker to push forged TEKs to any radio on the trunked
 * system — enabling bulk decryption of all subsequent traffic.
 */

#include <stdint.h>
#include <string.h>
#include "p25.h"

extern const uint8_t AGENCY_OTAR_ROOT_PUB[384];

struct otar_rekey_msg {
    uint32_t  kmf_id;
    uint32_t  target_radio_id;         /* WACN + System + Unit    */
    uint8_t   key_group;               /* OTAR key group          */
    uint8_t   algorithm_id;            /* 0x84 = AES-256          */
    uint16_t  key_id;                  /* SLN (Storage Location)  */
    uint8_t   wrapped_tek[256];        /* RSA-OAEP(TEK, radio_pk) */
    uint8_t   kmf_cert[2048]; size_t kmf_cert_len;
    uint8_t   kmf_sig[384];           /* over entire msg          */
};

int radio_accept_otar(const struct otar_rekey_msg *m)
{
    if (m->target_radio_id != radio_get_uid()) return OTAR_WRONG_UNIT;

    if (x509_chain_verify(m->kmf_cert, m->kmf_cert_len,
            AGENCY_OTAR_ROOT_PUB, sizeof AGENCY_OTAR_ROOT_PUB))
        return OTAR_CHAIN;

    uint8_t h[32];
    sha256_of(m, offsetof(struct otar_rekey_msg, kmf_cert), h);
    if (verify_with_cert(m->kmf_cert, m->kmf_cert_len,
                         h, m->kmf_sig, sizeof m->kmf_sig))
        return OTAR_SIG;

    /* Unwrap TEK using radio's RSA private key. */
    uint8_t tek[32]; size_t tlen = 32;
    if (crypto_module_rsa_oaep_decrypt(m->wrapped_tek, 256,
                                       tek, &tlen))
        return OTAR_UNWRAP;

    /* Install TEK into the radio's key store at SLN. */
    return crypto_module_install_key(m->key_id, m->algorithm_id,
                                     tek, tlen);
}

/* ---- Law-enforcement interception surface ------------------
 *  AGENCY_OTAR_ROOT factored:
 *    Push attacker-chosen TEKs to all radios on the trunked
 *    system. The attacker holds the same TEK -> decrypts all
 *    P25 voice traffic in real time. This defeats the entire
 *    purpose of P25 encryption.
 *
 *    Alternatively: push a null/weak TEK so traffic is
 *    effectively cleartext, eavesdropped by any SDR.
 *
 *  Per-radio RSA key factored:
 *    Decrypt any OTAR rekey message to that radio -> recover
 *    the TEK -> decrypt that radio's traffic. Also impersonate
 *    that radio (affiliate with the trunked system under its ID).
 *
 *  Impact: every US LE agency using P25 (>90% of state/local),
 *  plus Canadian RCMP, Australian APSP, UK Airwave (legacy P25).
 *  CJIS Security Policy §5.10.1.2 requires encrypted radio;
 *  OTAR is the mechanism.
 *
 *  Recovery: KMF issues new root + re-enrolls every radio.
 *  Large agency (NYPD: ~50k radios) = months of depot visits.
 * --------------------------------------------------------- */
