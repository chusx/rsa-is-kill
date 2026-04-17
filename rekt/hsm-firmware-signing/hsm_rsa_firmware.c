/*
 * hsm_rsa_firmware.c
 *
 * HSM firmware signing — RSA in Thales Luna, Utimaco, nCipher firmware authentication.
 *
 * Sources:
 *   - Thales Luna Network HSM 7 documentation (thales-group.com)
 *   - Utimaco SecurityServer documentation (utimaco.com)
 *   - Entrust nShield firmware update process documentation
 *   - Published research on HSM security (Carine Fédéric et al., Nohl et al.)
 *
 * Hardware Security Modules (HSMs) are used to protect cryptographic keys for:
 *   - Certificate Authorities (roots of trust for entire PKI hierarchies)
 *   - Payment HSMs (PIN verification, EMV, POS terminal master keys)
 *   - Signing HSMs (code signing, document signing, timestamping)
 *   - Key Management HSMs (enterprise key escrow, cloud KMS backends)
 *
 * Major HSM vendors and their firmware signing:
 *   Thales (formerly Gemalto) Luna:
 *     - Luna SA 5/6/7: RSA-2048 firmware signing cert, hardcoded in ROM
 *     - Luna T-Series (payment): RSA-2048 factory cert
 *     - Used by: Visa, Mastercard, major banks, CA/Browser Forum CAs
 *
 *   Utimaco SecurityServer:
 *     - CryptoServer Se-Series (general purpose): RSA-2048 firmware signing
 *     - CryptoServer CP5 (payment, PCI HSM certified): RSA-2048
 *     - Used by: Deutsche Bank, Bundesbank, German payment infrastructure
 *
 *   Entrust nShield:
 *     - nShield Edge/Connect/Solo: RSA-2048 firmware signing
 *     - Used by: Microsoft (Azure HSM), government PKIs, TSPs
 *
 *   Marvell/Cavium LiquidSecurity / Amazon AWS CloudHSM:
 *     - AWS CloudHSM uses Marvell hardware; RSA-2048 firmware auth
 *
 * The firmware signing key is burned into the HSM's security processor (ARM Cortex-M
 * or custom ASIC) at manufacture. The firmware image carries an RSA-2048 signature
 * that the bootloader verifies before loading.
 *
 * THE FUNDAMENTAL ISSUE:
 * An HSM protects cryptographic keys from software attacks.
 * The firmware authenticity is protected by RSA-2048.
 * If RSA-2048 is broken, an attacker can sign malicious HSM firmware.
 * Malicious HSM firmware can exfiltrate keys that the HSM was supposed to protect.
 * This collapses the entire trust model of the HSM.
 *
 * The attack:
 *   1. Factor HSM vendor's RSA-2048 firmware signing key public key
 *      (embedded in every HSM firmware image, often in vendor SDKs/documentation)
 *   2. Derive RSA-2048 private key
 *   3. Sign malicious firmware that exfiltrates all stored keys
 *   4. Update target HSM with malicious firmware (requires physical access or
 *      network access to management interface)
 *   5. Malicious firmware runs inside the HSM's "secure boundary"
 *   6. All keys "protected" by the HSM are compromised
 */

#include <stdint.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

/* HSM firmware image header (simplified generic model) */
struct hsm_fw_header {
    uint8_t  magic[8];           /* vendor-specific magic */
    uint32_t version;            /* firmware version */
    uint32_t hw_model;           /* hardware model ID */
    uint32_t image_len;
    uint8_t  sha256[32];         /* SHA-256 of firmware body */
    uint8_t  signature[256];     /* RSA-2048 PKCS#1 v1.5 signature */
    uint8_t  signing_cert[1024]; /* DER X.509 signing cert (RSA-2048) */
    /* Signing cert chains to the vendor ROM CA (burned in at manufacture) */
};

/*
 * hsm_verify_firmware() — verify RSA-2048 signature on HSM firmware update.
 *
 * Called by the HSM bootloader (running in the secure processor) before
 * loading any firmware update. The root CA public key is in ROM.
 * The firmware image contains the signing cert (RSA-2048), which must chain
 * to the ROM CA.
 *
 * THIS IS THE ONLY TECHNICAL CONTROL preventing malicious firmware from
 * running inside the HSM's hardware security boundary.
 *
 * If this check can be bypassed — either by exploiting the bootloader directly,
 * or by forging the RSA signature — an attacker can run arbitrary code inside
 * the HSM while the HSM's tamper sensors and secure boundary remain intact.
 * The HSM will report normal status while exfiltrating all stored keys.
 */
int
hsm_verify_firmware(const uint8_t *fw_image, size_t fw_len,
                     const uint8_t *rom_ca_cert_der, size_t rom_ca_len)
{
    const struct hsm_fw_header *hdr;
    const uint8_t *fw_body;
    uint8_t computed_sha256[32];
    const uint8_t *cert_p;
    X509 *signing_cert = NULL;
    X509 *rom_ca = NULL;
    EVP_PKEY *pubkey = NULL;
    EVP_MD_CTX *ctx = NULL;
    X509_STORE *store = NULL;
    X509_STORE_CTX *verify_ctx = NULL;
    int ret = -1;

    if (fw_len < sizeof(struct hsm_fw_header)) return -1;
    hdr = (const struct hsm_fw_header *)fw_image;
    fw_body = fw_image + sizeof(struct hsm_fw_header);

    /* Verify firmware body integrity */
    SHA256(fw_body, hdr->image_len, computed_sha256);
    if (memcmp(computed_sha256, hdr->sha256, 32) != 0) return -1;

    /* Decode ROM CA and signing cert */
    cert_p = rom_ca_cert_der;
    rom_ca = d2i_X509(NULL, &cert_p, (long)rom_ca_len);
    if (!rom_ca) return -1;

    cert_p = hdr->signing_cert;
    signing_cert = d2i_X509(NULL, &cert_p, sizeof(hdr->signing_cert));
    if (!signing_cert) goto out;

    /* Verify signing cert chains to ROM CA */
    store = X509_STORE_new();
    X509_STORE_add_cert(store, rom_ca);
    verify_ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(verify_ctx, store, signing_cert, NULL);
    if (X509_verify_cert(verify_ctx) != 1) goto out;  /* reject malicious firmware */

    /* Verify RSA-2048 PKCS#1 v1.5 signature */
    pubkey = X509_get_pubkey(signing_cert);
    ctx = EVP_MD_CTX_new();
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pubkey) <= 0) goto out;
    if (EVP_DigestVerifyUpdate(ctx, hdr->sha256, 32) <= 0) goto out;

    /* This RSA-2048 verify is the entire security basis of the HSM firmware model.
     * An attacker who can forge this signature can run anything inside the HSM. */
    ret = EVP_DigestVerifyFinal(ctx, hdr->signature, sizeof(hdr->signature));

out:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pubkey);
    X509_STORE_CTX_free(verify_ctx);
    X509_STORE_free(store);
    X509_free(signing_cert);
    X509_free(rom_ca);
    return ret;
}

/*
 * hsm_malicious_firmware_payload() — conceptual model of what malicious HSM firmware does.
 *
 * Once malicious firmware is running inside an HSM, it can:
 *   1. Enumerate all key objects stored in the HSM
 *   2. Use the HSM's own key extraction commands (the HSM API calls itself)
 *   3. Export key material through a side channel (e.g., crafting specific
 *      RSA output values, timing channels, or a firmware-added network channel)
 *   4. The HSM's physical tamper protection is irrelevant — the attack is firmware-level
 *
 * For a Thales Luna used as a Root CA HSM:
 *   - The CA private key is "protected" in the HSM
 *   - Malicious firmware extracts it
 *   - Attacker now has the Root CA private key
 *   - Issues arbitrary certificates trusted by every system in the CA hierarchy
 *
 * For a payment HSM:
 *   - PIN encryption keys, zone master keys (ZMK), terminal master keys (TMK) extracted
 *   - Attacker can decrypt all PIN blocks from any terminal using that HSM
 *   - Full financial transaction compromise
 */
void hsm_malicious_firmware_note(void)
{
    /*
     * Thales Luna SA 7 firmware signing cert public key:
     *   Subject: CN=Thales Luna Firmware CA
     *   Algorithm: RSA-2048
     *   Modulus: extractable from any Luna firmware image
     *
     * Luna firmware updates (.fuf files) are distributed to customers via
     * Thales support portal. The signing cert is embedded in the firmware file.
     * Factor it -> sign arbitrary .fuf file -> load on any Luna SA 7.
     *
     * Utimaco SecurityServer firmware:
     *   Firmware signing via "csadm" tool; RSA-2048 signing cert embedded in .bin file.
     *   Factory cert extractable from any firmware update package.
     *
     * nShield firmware (.nff files):
     *   Entrust/Thales nShield firmware files contain RSA-2048 signing cert.
     *   nShield is used in: Microsoft Azure Dedicated HSM, AWS CloudHSM (Cavium),
     *   many commercial TSP (timestamping authority) deployments.
     */
    (void)0;
}
