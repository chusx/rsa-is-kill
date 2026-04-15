/*
 * tr34_rkl_session.c
 *
 * ANSI X9 TR-34 Remote Key Loading between an ATM's Encrypting PIN
 * Pad (EPP) and a bank's Key Distribution Host. Carries the Terminal
 * Master Key (TMK) under RSA-OAEP wrap; every subsequent PIN block
 * at that ATM is protected by keys derived from this TMK.
 *
 * Implemented by Thales payShield / Futurex Excrypt / Atalla AT1000
 * on the bank side, and inside Diebold-Nixdorf ProCash, NCR SelfServ,
 * Hyosung MonixX EPP firmware on the ATM side.
 */

#include <stdint.h>
#include <string.h>
#include "tr34.h"
#include "rsa_oaep.h"
#include "cms.h"

/* TR-34 CMS envelope types */
enum tr34_msg {
    TR34_KDH_UNSIGNED_TOKEN = 0x01,  /* Key Distribution Host → ATM */
    TR34_KRD_BIND_TOKEN     = 0x02,  /* ATM → KDH, binding EPP cert */
    TR34_KTE_UNILATERAL     = 0x03,  /* two-pass key transport */
    TR34_KTE_BILATERAL      = 0x04,  /* three-pass with KDH signature */
};

struct epp_identity {
    char        serial[24];          /* burned at manufacture */
    uint8_t     epp_cert_der[2048];  /* RSA-2048 EPP leaf, signed by
                                        vendor MFG CA, cross-signed by
                                        bank's KDH CA during commission */
    size_t      epp_cert_len;
    uint8_t     epp_priv_handle;     /* opaque HSM ref, tamper-protected */
};


/* Step 1: ATM power-up; EPP publishes a CMS-wrapped Credential Token
 *         binding its cert + serial + challenge (nonce).  The KDH
 *         reads this, validates the chain to its pinned root CA. */

int tr34_epp_emit_credential_token(struct epp_identity *epp,
                                    uint8_t *out, size_t *out_len)
{
    struct tr34_cred_token t = { 0 };
    memcpy(t.serial, epp->serial, 24);
    memcpy(t.epp_cert, epp->epp_cert_der, epp->epp_cert_len);
    t.epp_cert_len = epp->epp_cert_len;
    rand_bytes(t.nonce, 16);

    /* SignedData, EPP-signed with its RSA-2048 private key */
    return cms_signed_data_build(
        &t, sizeof t,
        epp->epp_priv_handle,
        epp->epp_cert_der, epp->epp_cert_len,
        out, out_len);
}


/* Step 2: KDH returns an unsigned Key Token — an RSA-OAEP blob
 *         containing the TMK, wrapped to the EPP's pubkey, inside
 *         a CMS EnvelopedData.  Optional KDH signature wraps the
 *         whole thing for bilateral mode. */

int tr34_epp_ingest_key_token(struct epp_identity *epp,
                               const uint8_t *token, size_t len,
                               uint8_t tmk_out[32], size_t *tmk_len_out,
                               int expected_bilateral,
                               const uint8_t *kdh_ca_pub, size_t kdh_ca_pub_len)
{
    /* Bilateral: verify KDH signature chain first. */
    if (expected_bilateral) {
        if (cms_signed_data_verify_chain(token, len,
                                         kdh_ca_pub, kdh_ca_pub_len) != 0)
            return TR34_ERR_KDH_SIG_INVALID;
    }

    /* Extract inner EnvelopedData, find our KeyTransRecipientInfo. */
    uint8_t enc_tmk[512]; size_t enc_tmk_len;
    if (cms_enveloped_get_recipient_blob(
            token, len,
            epp->epp_cert_der, epp->epp_cert_len,
            enc_tmk, sizeof enc_tmk, &enc_tmk_len) != 0)
        return TR34_ERR_RECIPIENT_NOT_FOUND;

    /* RSA-OAEP unwrap with EPP private key, inside tamper-responsive
     * HSM. This is the primitive that collapses under a factoring
     * attack on the EPP keypair. */
    if (rsa_oaep_unwrap(epp->epp_priv_handle,
                         enc_tmk, enc_tmk_len,
                         tmk_out, 32, tmk_len_out) != 0)
        return TR34_ERR_UNWRAP_FAIL;

    /* Install TMK into key-ladder register; subsequent PIN encryption
     * uses derived Session Working Keys (SWK) via X9.24-3 key
     * derivation.  The TMK itself never leaves the EPP secure
     * boundary after this point. */
    epp_key_ladder_install(KEYREG_TMK, tmk_out, *tmk_len_out);
    memset(tmk_out, 0, 32);          /* scrub stack copy */
    return TR34_OK;
}


/* Step 3: Post-RKL — every customer transaction */

int atm_encrypt_pin_block(const char *pan, const char *pin,
                           uint8_t out_pinblock[8])
{
    uint8_t pinblock_plain[8];
    iso9564_fmt0_encode(pan, pin, pinblock_plain);

    /* Derive per-transaction PIN encryption key from TMK. */
    uint8_t pek[16];
    key_ladder_derive(KEYREG_TMK, DERIVE_PEK, pek, sizeof pek);

    tdes_ede3_cbc_encrypt(pek, pinblock_plain, 8, out_pinblock);
    memset(pek, 0, sizeof pek);
    return 0;
}


/* ---- Breakage ----
 *
 *   Factor the EPP's RSA-2048 keypair → attacker unwraps TR-34 key
 *   tokens captured off the wire and recovers the TMK. Every PIN
 *   block encrypted at that ATM since the current TMK was loaded
 *   is decryptable offline. In practice, combine with an on-ATM
 *   network tap (or a compromised acquirer switch that logs ISO
 *   8583 traffic) and the attacker reconstructs customer PANs +
 *   PINs at will. This is why EPP RSA keys are burned into tamper-
 *   responsive hardware; a *math* break on RSA sidesteps the tamper
 *   protection entirely.
 *
 *   Factor the KDH CA → attacker mints a KDH cert, runs a rogue
 *   RKL host, and injects a known TMK into any ATM on the
 *   acquirer's network that hasn't pinned the specific KDH leaf
 *   cert (most deployments pin only the root). All subsequent PIN
 *   traffic from that ATM becomes attacker-readable.
 *
 *   Factor the vendor firmware key → signed malicious firmware
 *   flash across a global ATM fleet; jackpot / PIN-skim at scale.
 */
