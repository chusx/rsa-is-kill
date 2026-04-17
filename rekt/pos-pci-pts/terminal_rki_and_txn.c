/*
 * terminal_rki_and_txn.c
 *
 * End-to-end integration path on a PCI-PTS POI terminal:
 *
 *   Factory → Vendor cert-issuance into SCR → RKI by merchant
 *   acquirer → DUKPT IPEK installed → every transaction uses
 *   derived KSN-indexed keys for PIN-block encryption; acquirer
 *   TLS session wraps the ISO 8583 ARQC upstream.
 *
 * All four points involve RSA. Implemented in Verifone Engage,
 * Ingenico Tetra, PAX Prolin / Android POS variants.
 */

#include <stdint.h>
#include <string.h>
#include "pci_poi.h"
#include "rsa_oaep.h"
#include "dukpt.h"
#include "iso8583.h"

/* ---------------- 1. Factory provisioning ---------------------- */

/* At manufacturing, the SCR (Secure Card Reader) module generates an
 * RSA-2048 keypair inside its tamper-responsive boundary. The
 * public half is exported, signed by the vendor PTS CA, and the
 * resulting X.509 cert is written into the SCR's protected cert
 * slot. Private key never leaves the SCR. */

struct poi_identity {
    char       serial[16];
    uint8_t    poi_cert_der[1536];   /* RSA-2048 leaf, signed by vendor CA */
    size_t     poi_cert_len;
    uint32_t   rsa_priv_handle;      /* opaque HSM ref */
};


/* ---------------- 2. Remote Key Injection (RKI) --------------- */

/*
 * Acquirer's Key Injection Facility (KIF) → POI:
 *
 *   - KIF fetches the POI's public cert (lookup by serial in the
 *     merchant-bound database).
 *   - KIF selects a BDK (Base Derivation Key) slot; derives an
 *     IPEK (Initial PIN Encryption Key) for this specific terminal
 *     using DUKPT rules (X9.24-3) — one BDK serves hundreds of
 *     thousands of terminals, each with a unique IPEK.
 *   - KIF RSA-OAEP wraps the IPEK to the POI's pubkey.
 *   - KIF sends CMS EnvelopedData + KDH cert to POI.
 *   - POI verifies KDH cert chain up to the acquirer root, RSA-OAEP
 *     unwraps the IPEK into a tamper-protected key slot.
 */

int poi_ingest_ipek_blob(struct poi_identity *poi,
                          const uint8_t *cms_enveloped, size_t len,
                          const uint8_t *acq_root_pub, size_t acq_root_pub_len)
{
    /* chain-verify the KDH signer cert */
    if (cms_verify_signer_chain(cms_enveloped, len,
                                 acq_root_pub, acq_root_pub_len) != 0)
        return POI_ERR_KDH_CHAIN;

    /* Extract RSA-OAEP blob addressed to us */
    uint8_t wrapped[512]; size_t wrapped_len;
    if (cms_get_recipient(cms_enveloped, len,
                          poi->poi_cert_der, poi->poi_cert_len,
                          wrapped, sizeof wrapped, &wrapped_len) != 0)
        return POI_ERR_NO_RECIPIENT;

    /* RSA-OAEP unwrap inside SCR */
    uint8_t ipek[16];
    size_t ipek_len;
    if (rsa_oaep_unwrap(poi->rsa_priv_handle,
                         wrapped, wrapped_len,
                         ipek, sizeof ipek, &ipek_len) != 0)
        return POI_ERR_UNWRAP_FAIL;

    /* Install IPEK + KSN (Key Serial Number) into DUKPT state */
    dukpt_install_ipek(DUKPT_SLOT_PIN, ipek, ipek_len, /*initial_ksn=*/NULL);
    memset(ipek, 0, sizeof ipek);
    return POI_OK;
}


/* ---------------- 3. Per-transaction PIN encryption ------------ */

int poi_encrypt_pinblock(const char *pan, const char *pin,
                          uint8_t out[8], uint8_t ksn_out[10])
{
    uint8_t pinblock[8];
    iso9564_fmt4_encode(pan, pin, pinblock);

    /* DUKPT: derive a fresh per-txn key from IPEK+counter */
    uint8_t txn_key[16];
    dukpt_derive_next_txn_key(DUKPT_SLOT_PIN, txn_key, ksn_out);

    aes128_ecb_encrypt(txn_key, pinblock, 8, out);
    memset(txn_key, 0, sizeof txn_key);
    return 0;
}


/* ---------------- 4. Authorization over TLS to acquirer ------- */

int poi_send_auth_request(uint32_t amount_cents, const char *pan,
                           const char *pin, uint8_t emv_arqc[8])
{
    uint8_t enc_pinblock[8];
    uint8_t ksn[10];
    poi_encrypt_pinblock(pan, pin, enc_pinblock, ksn);

    /* Build ISO 8583 0200 message */
    iso8583_msg_t m = {0};
    iso8583_set_mti(&m, 0x0200);
    iso8583_set_field(&m, 2, pan, strlen(pan));
    iso8583_set_field(&m, 4, &amount_cents, sizeof amount_cents);
    iso8583_set_field(&m, 52, enc_pinblock, sizeof enc_pinblock);
    iso8583_set_field(&m, 53, ksn, sizeof ksn);
    iso8583_set_field(&m, 55, emv_arqc, 8);    /* EMV cryptogram */

    /* TLS 1.2+ to acquirer. Server cert chain verified against
     * card-network root (Visa/MC/Amex) pinned in terminal. Mutual
     * auth in P2PE flows. RSA-2048 server cert is the handshake
     * primitive. */
    return tls_post_to_acquirer(&m);
}


/* ---- Breakage ----
 *
 *   Factor the POI SCR's RSA-2048 keypair:
 *     - attacker captures the CMS-wrapped IPEK off the RKI wire
 *       (or extracts it from merchant-side logs), unwraps offline,
 *       now derives every DUKPT per-txn PIN-encryption key and
 *       decrypts every field-52 PIN block from that terminal.
 *     - Combined with a packet capture on the merchant LAN, the
 *       attacker builds a stream of PAN+PIN pairs for every
 *       card transacted at that POS.
 *
 *   Factor the terminal-vendor firmware-signing key:
 *     - Distribute a malicious Engage / Tetra / Prolin firmware
 *       accepted by every terminal's secure bootloader. Attacker
 *       harvests magstripe + ICC + PIN pre-encryption. Merchant
 *       and acquirer have no indication that firmware is hostile.
 *
 *   Factor the acquirer's RKI CA:
 *     - Mint a KDH cert; inject a known BDK-derivation into any
 *       POI in the acquirer's estate. Fleet-wide PIN-harvesting
 *       at that acquirer.
 *
 *   Factor a card-network TLS root (Visa Transaction Security,
 *   Mastercard Encryption):
 *     - MITM authorization traffic to the network. Forged 0210
 *       approval responses, transaction replay, chargeback
 *       manipulation at cross-acquirer scale.
 */
