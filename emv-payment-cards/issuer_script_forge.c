/*
 * issuer_script_forge.c
 *
 * EMV Issuer Script processing (EMV Book 3, §10.10). After
 * an online authorization, the issuer (bank) can push a
 * signed Issuer Script (IS1/IS2) to the card through the
 * terminal. Scripts can:
 *   - Block the card (disable application)
 *   - Unblock the PIN
 *   - Update the PIN try counter
 *   - Put/Get Data on internal card files
 *   - Load/install MULTOS or GP applets (on supported cards)
 *
 * Issuer Scripts are MAC'd under the Session Key derived from
 * the Card Master Key (MK-AC), which is itself derived from the
 * Issuer Master Key (IMK). For "CDA" (Combined Data Authentication)
 * cards — which are the vast majority of EMV chips post-2015 —
 * the offline data authentication path is RSA (the ICC Public Key
 * and the Issuer Public Key are both RSA). An attacker with a
 * factored Issuer Public Key can forge offline transactions and,
 * combined with compromised session-key derivation, Issuer Scripts.
 *
 * Separately, the EMV CA Public Key (root, published in EMVCo
 * bulletins) is RSA; factoring it compromises EVERY card on that
 * payment scheme (Visa, Mastercard, Amex, UnionPay).
 */

#include <stdint.h>
#include <string.h>
#include "emv.h"

extern const uint8_t EMVCO_CA_PUB[];  /* RSA-1984 / RSA-2048 */
extern size_t EMVCO_CA_PUB_LEN;

/* EMV CDA Static Data Authentication: the card stores a
 * signed block containing ICC Public Key and card-specific
 * static data. Verification chain:
 *   EMVCo CA PK  ->  Issuer PK  ->  ICC PK  ->  dynamic sig */

struct emv_icc_pk_cert {
    uint8_t   recovered[256];          /* RSA decrypted block    */
    /* After recovery:
     *   [0]     = 0x6A (header)
     *   [1]     = 0x04 (ICC PK cert format)
     *   [2..11] = PAN (Application Primary Account Number)
     *   [12]    = certificate expiry (MMYY BCD)
     *   [14]    = certificate serial number (3 bytes)
     *   [17]    = hash algorithm indicator (01 = SHA-1)
     *   [18]    = ICC public key algorithm (01 = RSA)
     *   [19]    = ICC public key length
     *   [20]    = ICC public key exponent length
     *   [21..N] = leftmost digits of ICC public key
     *   [N+1..N+20] = SHA-1 hash
     *   [N+21]  = 0xBC (trailer)
     */
};

int emv_recover_icc_pk(const uint8_t *issuer_pk_mod,
                        size_t issuer_pk_len,
                        const uint8_t *icc_pk_cert,
                        size_t icc_pk_cert_len,
                        const uint8_t *icc_pk_remainder,
                        size_t icc_pk_rem_len,
                        uint8_t *icc_pk_out,
                        size_t *icc_pk_out_len)
{
    /* RSA public-key recovery (EMV Book 2, §6.4).
     * This is RSA "decryption" with the issuer public key. */
    uint8_t rec[256];
    rsa_public_recover(issuer_pk_mod, issuer_pk_len,
                       (uint8_t[]){0x01,0x00,0x01}, 3,
                       icc_pk_cert, icc_pk_cert_len,
                       rec, sizeof rec);
    if (rec[0] != 0x6A || rec[icc_pk_cert_len-1] != 0xBC)
        return EMV_ERR_FORMAT;

    /* SHA-1 over (cert_data || remainder || exponent) */
    uint8_t h[20];
    sha1_emv_icc_pk(rec, icc_pk_cert_len,
                    icc_pk_remainder, icc_pk_rem_len, h);
    if (memcmp(h, rec + icc_pk_cert_len - 21, 20))
        return EMV_ERR_HASH;

    size_t klen = rec[19];
    memcpy(icc_pk_out, rec + 21, klen);
    if (icc_pk_rem_len)
        memcpy(icc_pk_out + klen, icc_pk_remainder, icc_pk_rem_len);
    *icc_pk_out_len = klen + icc_pk_rem_len;
    return 0;
}

/* =========================================================
 *  Issuer Script template builder. This is what a PoC
 *  attacker would forge once the Issuer Private Key is
 *  recovered via the factored Issuer Public Key.
 * ========================================================= */
struct issuer_script_cmd {
    uint8_t   tag;                     /* 0x71 (IS1) / 0x72 (IS2) */
    uint8_t   len;
    uint8_t   cmd_apdu[255];
    /* e.g. INS=0x84 (Application Block) for card-kill;
     *      INS=0x24 (PIN Change/Unblock) for PIN abuse;
     *      INS=0xDA (Put Data) for file rewrite. */
};

int terminal_process_issuer_script(const uint8_t *tlv, size_t len)
{
    while (len > 2) {
        uint8_t tag = tlv[0];
        uint8_t slen = tlv[1];
        if (tag != 0x71 && tag != 0x72) { tlv += 2+slen; len -= 2+slen; continue; }
        /* Send APDU to the card via C-APDU. Card authenticates
         * via Session MAC derived from MK-AC. */
        uint16_t sw;
        card_send_apdu(tlv + 2, slen, &sw);
        /* SW = 0x9000 on success; card logs result in
         * Issuer Script Results (tag 0xDF8101). */
        tlv += 2 + slen; len -= 2 + slen;
    }
    return 0;
}

/* ---- Break consequence ------------------------------------
 *  EMVCO_CA_PUB factored (e.g. Visa CA PK index 09, RSA-1984):
 *    Forge Issuer PK Certificates for any BIN; every terminal
 *    on the planet validates the chain. Offline CDA transactions
 *    accepted without online authorization. Global card fraud
 *    at payment-network scale; EMVCo must rotate every CA index
 *    across ~5 billion active cards.
 *
 *  Issuer PK factored (per-bank, RSA-1408/1984):
 *    Forge ICC PK certs for any PAN within that BIN. Offline
 *    cloning of any cardholder's chip identity. Issuer Script
 *    forgery allows mass card-block or PIN-unblock.
 *
 *  Recovery: EMVCo issues new CA PKs; every terminal's AID
 *  config must be updated; every card re-personalized.
 *  Multi-year, multi-billion-dollar global effort.
 * --------------------------------------------------------- */
