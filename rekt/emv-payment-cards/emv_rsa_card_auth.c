/*
 * Illustrative code based on EMV Contactless Specifications Book 2 (CCD)
 * and EMV Book 2: Security and Key Management.
 *
 * EMV (Europay/Mastercard/Visa) is the global standard for chip payment cards.
 * ~10 billion EMV cards are in circulation (2024). Every payment terminal
 * worldwide (Visa, Mastercard, Amex, UnionPay) implements this protocol.
 *
 * EMV card authentication mechanisms, all using RSA:
 *
 *   SDA (Static Data Authentication):
 *     - Card data signed with RSA-1024 by the issuing bank CA
 *     - Terminal verifies signature with bank CA public key (from Visa/MC PKI)
 *     - RSA-1024: classically deprecated; factored at ~$10M in 2024
 *
 *   DDA (Dynamic Data Authentication):
 *     - Card has its own RSA-1024 or RSA-2048 keypair (in secure element)
 *     - Terminal sends a random challenge; card signs it with RSA private key
 *     - Proves card is genuine (ICC private key never leaves the chip)
 *
 *   CDA (Combined Dynamic Data Authentication / Application Cryptogram):
 *     - RSA-2048 signature over transaction data + ARQC (application cryptogram)
 *     - Most modern EMV cards use this
 *
 * No PQC mechanism is defined in EMV specifications. Visa/Mastercard
 * have not published a PQC migration roadmap as of 2026.
 */

#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <stdint.h>

/* EMV CA Public Key lengths: Visa uses RSA-1152 and RSA-2048 modules.
 * Mastercard uses RSA-1408 and RSA-2048. Legacy keys go back to RSA-1024. */
#define EMV_RSA_1024_BYTES   128
#define EMV_RSA_1152_BYTES   144   /* Visa: 1152-bit, a non-standard size */
#define EMV_RSA_2048_BYTES   256

/*
 * EMV Certification Authority (CA) Public Key Registry:
 * Visa: https://www.visa.com/chip (8 active CA public keys, some RSA-1152)
 * Mastercard: published in EMV L3 test tools (RSA-1408, RSA-2048)
 * These CA keys are loaded into every payment terminal at deployment.
 * They are used to verify issuer certificates which verify card certificates.
 */
typedef struct {
    uint8_t  rid[5];            /* Registered Application Provider ID (e.g., Visa: A000000003) */
    uint8_t  index;             /* CA Public Key Index (distinguishes active keys) */
    uint8_t  modulus[256];      /* Up to RSA-2048 modulus */
    uint16_t modulus_len;       /* 128 / 144 / 176 / 256 bytes */
    uint32_t exponent;          /* Public exponent: 3 or 65537 */
    uint8_t  hash[20];          /* SHA-1 fingerprint of this CA key */
} EMV_CA_PublicKey;

/*
 * SDA: Static Data Authentication (EMV Book 2 §5.3)
 * The Signed Static Application Data (SSAD) is pre-computed by the issuer.
 * Format: RSA PKCS#1 v1.5 signature over card data, signed by Issuer key.
 * The Issuer key itself is signed by the CA key (RSA chain).
 *
 * Break the CA RSA key → forge any card's SSAD → clone unlimited SDA cards.
 */
int emv_verify_sda(const uint8_t *ssad,         /* Signed Static Application Data */
                   uint16_t ssad_len,
                   const EMV_CA_PublicKey *ca_key,
                   const uint8_t *issuer_cert,   /* Issuer Public Key Certificate */
                   uint16_t issuer_cert_len)
{
    RSA *ca_rsa = RSA_new();
    BIGNUM *n = BN_bin2bn(ca_key->modulus, ca_key->modulus_len, NULL);
    BIGNUM *e = BN_new();
    BN_set_word(e, ca_key->exponent);
    RSA_set0_key(ca_rsa, n, e, NULL);

    uint8_t decrypted[256];
    /* RSA public key operation: decrypted = issuer_cert^e mod n */
    int len = RSA_public_decrypt(issuer_cert_len, issuer_cert, decrypted,
                                 ca_rsa, RSA_NO_PADDING);
    /* Remainder of SDA: parse issuer key from decrypted, verify SSAD with issuer key */
    RSA_free(ca_rsa);
    return (len > 0) ? 0 : -1;
}

/*
 * DDA: Dynamic Data Authentication (EMV Book 2 §6.3)
 * The ICC (Integrated Circuit Card) holds an RSA keypair in its secure element.
 * The ICC Certificate is issued by the Issuer, signed with the Issuer RSA key.
 * At transaction time, terminal sends an 8-byte random number (DDOL).
 * Card signs DDOL with its ICC private key — proves non-cloneability.
 *
 * With CRQC: factor the ICC public key (from ICC Certificate) → recover ICC
 * private key → clone card signatures → unlimited fraudulent DDA transactions.
 */
int emv_verify_dda(const uint8_t *icc_cert,      /* ICC Public Key Certificate */
                   uint16_t icc_cert_len,
                   const uint8_t *dynamic_sig,    /* Signed Dynamic Application Data */
                   uint16_t sig_len,
                   const uint8_t *ddol,           /* Dynamic Data Object List response */
                   uint16_t ddol_len,
                   RSA *issuer_rsa_key)           /* RSA-1024 or RSA-2048 */
{
    uint8_t icc_pubkey_modulus[256];
    /* Step 1: recover ICC public key from certificate using Issuer RSA key */
    RSA_public_decrypt(icc_cert_len, icc_cert, icc_pubkey_modulus,
                       issuer_rsa_key, RSA_NO_PADDING);

    /* Step 2: verify dynamic signature with ICC public key + SHA-1 */
    RSA *icc_rsa = RSA_new();
    BIGNUM *n = BN_bin2bn(icc_pubkey_modulus, sig_len, NULL);
    BIGNUM *e = BN_new(); BN_set_word(e, 3);   /* some cards use e=3 */
    RSA_set0_key(icc_rsa, n, e, NULL);

    uint8_t decrypted_sig[256];
    int ret = RSA_public_decrypt(sig_len, dynamic_sig, decrypted_sig,
                                 icc_rsa, RSA_NO_PADDING);
    /* Verify SHA-1(DDOL) inside decrypted_sig */
    RSA_free(icc_rsa);
    return (ret > 0) ? 0 : -1;
}

/*
 * Payment card lifespan: 3-5 years (banks reissue cards on schedule).
 * Migration path: reissue cards with PQC keys — feasible but requires:
 *   1. EMV specification updates (Visa, Mastercard, Amex, UnionPay all agree)
 *   2. New CA key ceremony with PQC root
 *   3. Terminal firmware updates (10M+ terminals globally)
 *   4. HSM updates at every card personalization bureau
 *   5. Reissue ~10 billion cards
 *
 * The 3-5yr card lifespan is the most favorable scenario — but only if
 * migration starts before a CRQC is operational.
 * Harvest-Now-Decrypt-Later: stored RSA signatures on historical transactions
 * cannot be retroactively forged, but live key recovery enables real-time fraud.
 */
