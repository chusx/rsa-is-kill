/*
 * dvb_ci_ake.c
 *
 * DVB-CI Plus — Authentication and Key Exchange between host and CAM.
 * Sources:
 *   - CI Plus v1.4 Specification (CI+ Forum, 2016)
 *   - ETSI EN 50221 (Common Interface for DVB)
 *   - CI Plus Licensee Specifications (closed, member-only)
 *
 * The CI+ Root CA is operated by "CI Plus LLP" (through Trusted Labs, France).
 * Its RSA-2048 public key is embedded in every CI+-certified device.
 *
 * Trust chain:
 *
 *       CI Plus Root CA        (RSA-2048, long-term)
 *             |
 *     +-------+-------+--------+----------+
 *     |       |       |        |          |
 *    BrandA BrandB Neotion  SMiT   Smardtv ... (Brand/CAM CAs)
 *     |       |       |        |          |
 *    hosts  hosts   CAMs     CAMs      CAMs
 *   (RSA-2048 device certs, one per manufactured TV/STB/CAM)
 *
 * CI+ AKE protocol (simplified):
 *
 *   Host                                        CAM
 *   ----                                        ---
 *   auth_req (hostCert, DH_A)       -->
 *                                    <--  auth_resp (camCert, DH_B, sig_CAM)
 *   # host verifies camCert chain against CI+ Root
 *   # host verifies sig_CAM = RSA-sign(SK_CAM, hash(DH_A || DH_B))
 *   auth_ack (sig_HOST)              -->
 *   # CAM verifies sig_HOST = RSA-sign(SK_HOST, hash(DH_B || DH_A))
 *   # both derive AuthKey AKH from DH_A^b = DH_B^a
 *   # subsequent Content Control messages AES-128-CBC with keys from AKH
 */

#include <stdint.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#define CI_PLUS_CERT_MAX_LEN     2048
#define CI_PLUS_RSA_KEY_BYTES    256    /* RSA-2048 */
#define CI_PLUS_DH_MODULUS_BYTES 256    /* 2048-bit MODP group */
#define CI_PLUS_AKH_BYTES        32     /* Auth Key Host — 256-bit */

/* CI+ Root CA RSA-2048 public key — embedded in every CI+ device firmware.
 * Published in the CI+ Licensee Specification, Annex C. */
static const uint8_t CI_PLUS_ROOT_MODULUS[CI_PLUS_RSA_KEY_BYTES] = { 0 };
static const uint8_t CI_PLUS_ROOT_EXPONENT[3] = { 0x01, 0x00, 0x01 };

struct ci_plus_device_cert {
    uint8_t  cert_der[CI_PLUS_CERT_MAX_LEN];
    size_t   cert_len;
    uint8_t  device_id[20];           /* CI+ device identifier */
    uint8_t  manufacturer_ca_cert_der[CI_PLUS_CERT_MAX_LEN];
    size_t   manufacturer_ca_cert_len;
};

/*
 * ci_plus_verify_device_cert — verify a peer's device certificate chains
 * to the CI+ Root. Called by both host (on CAM insertion) and CAM (when
 * authenticating the host). Runs on every CAM/host AKE.
 */
int
ci_plus_verify_device_cert(const struct ci_plus_device_cert *cert)
{
    const uint8_t *p = cert->manufacturer_ca_cert_der;
    X509 *mfg_ca = d2i_X509(NULL, &p, cert->manufacturer_ca_cert_len);
    if (!mfg_ca) return -1;

    /* Verify manufacturer CA cert was signed by CI+ Root */
    RSA *root = RSA_new();
    BIGNUM *n = BN_bin2bn(CI_PLUS_ROOT_MODULUS, CI_PLUS_RSA_KEY_BYTES, NULL);
    BIGNUM *e = BN_bin2bn(CI_PLUS_ROOT_EXPONENT, 3, NULL);
    RSA_set0_key(root, n, e, NULL);

    EVP_PKEY *root_pkey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(root_pkey, root);

    int ok = X509_verify(mfg_ca, root_pkey);
    if (!ok) { X509_free(mfg_ca); EVP_PKEY_free(root_pkey); RSA_free(root); return -1; }

    /* Verify device cert was signed by manufacturer CA */
    p = cert->cert_der;
    X509 *device = d2i_X509(NULL, &p, cert->cert_len);
    EVP_PKEY *mfg_pkey = X509_get_pubkey(mfg_ca);
    ok = X509_verify(device, mfg_pkey);

    EVP_PKEY_free(mfg_pkey);
    EVP_PKEY_free(root_pkey);
    X509_free(device);
    X509_free(mfg_ca);
    RSA_free(root);
    return ok ? 0 : -1;
}

/*
 * ci_plus_ake_derive_akey — complete the AKE after both sides have verified
 * each other's certs and exchanged DH contributions + RSA signatures.
 *
 * The AuthKey Host (AKH) seeds the Content Control key ladder that
 * encrypts every subsequent payload on the CI+ interface.
 */
int
ci_plus_ake_derive_akey(DH *local_dh,
                         const uint8_t peer_pubkey[CI_PLUS_DH_MODULUS_BYTES],
                         const uint8_t peer_rsa_signature[CI_PLUS_RSA_KEY_BYTES],
                         RSA *peer_rsa_pubkey,
                         uint8_t akh_out[CI_PLUS_AKH_BYTES])
{
    /* Verify peer's RSA-2048 signature over DH contributions */
    uint8_t local_pub[CI_PLUS_DH_MODULUS_BYTES] = {0};
    const BIGNUM *pub_bn;
    DH_get0_key(local_dh, &pub_bn, NULL);
    BN_bn2binpad(pub_bn, local_pub, CI_PLUS_DH_MODULUS_BYTES);

    uint8_t signed_data[2 * CI_PLUS_DH_MODULUS_BYTES];
    memcpy(signed_data, peer_pubkey, CI_PLUS_DH_MODULUS_BYTES);
    memcpy(signed_data + CI_PLUS_DH_MODULUS_BYTES, local_pub, CI_PLUS_DH_MODULUS_BYTES);

    uint8_t hash[32];
    SHA256(signed_data, sizeof(signed_data), hash);

    if (!RSA_verify(NID_sha256, hash, 32,
                     peer_rsa_signature, CI_PLUS_RSA_KEY_BYTES,
                     peer_rsa_pubkey))
        return -1;

    /* Compute DH shared secret */
    BIGNUM *peer_bn = BN_bin2bn(peer_pubkey, CI_PLUS_DH_MODULUS_BYTES, NULL);
    uint8_t shared[CI_PLUS_DH_MODULUS_BYTES];
    int shared_len = DH_compute_key(shared, peer_bn, local_dh);
    BN_free(peer_bn);
    if (shared_len <= 0) return -1;

    /* AKH = SHA-256(shared secret) — simplified. Real CI+ key ladder
     * uses multiple derivation steps per CI+ spec §8.3. */
    SHA256(shared, shared_len, akh_out);
    return 0;
}

/*
 * ci_plus_decrypt_cw — decrypt Control Words received from the CAM.
 * The CW is the actual CSA/AES broadcast key that decrypts the TS stream.
 * The CAM computes CWs from the smart card's ECM processing and hands them
 * to the host over the CI+ interface, encrypted with the current CC key
 * (derived from AKH).
 *
 * An attacker with a forged host cert authenticates to any CAM, derives
 * AKH, and then receives decrypted CWs for the active broadcast channel.
 */
int
ci_plus_decrypt_cw(const uint8_t *encrypted_cw, size_t len,
                    const uint8_t cc_key[16],
                    uint8_t *cw_out)
{
    /* CI+ Content Control uses AES-128-CBC with per-message IV */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, cc_key, NULL);
    int outlen;
    EVP_DecryptUpdate(ctx, cw_out, &outlen, encrypted_cw, len);
    EVP_CIPHER_CTX_free(ctx);
    return outlen;
}

/*
 * ci_plus_revoke_check — check a peer device certificate against the
 * current Revocation Message List (RML). RML is signed by the CI+ Root
 * and updated via broadcast EMM or via CAM firmware updates.
 *
 * A factored CI+ Root key lets an attacker:
 *   - Unrevoke their own previously-compromised CAM/host certs
 *   - Revoke competitors' legitimate device certs (DOS)
 */
int
ci_plus_revoke_check(const uint8_t *device_id,
                      const uint8_t *rml_data, size_t rml_len,
                      const uint8_t *rml_signature)
{
    /* Verify RML signature with CI+ Root public key */
    RSA *root = RSA_new();
    BIGNUM *n = BN_bin2bn(CI_PLUS_ROOT_MODULUS, CI_PLUS_RSA_KEY_BYTES, NULL);
    BIGNUM *e = BN_bin2bn(CI_PLUS_ROOT_EXPONENT, 3, NULL);
    RSA_set0_key(root, n, e, NULL);

    uint8_t hash[32];
    SHA256(rml_data, rml_len, hash);

    int sig_ok = RSA_verify(NID_sha256, hash, 32,
                             rml_signature, CI_PLUS_RSA_KEY_BYTES, root);
    RSA_free(root);
    if (!sig_ok) return -1;

    /* ... search RML entries for device_id ... */
    return 0;
}

/*
 * Attack chain:
 *
 *  1. CI+ Root public key modulus is published in CI Plus Licensee
 *     Specification Annex C, distributed to every TV/CAM manufacturer.
 *     Leaked copies are on the public internet.
 *
 *  2. Factor RSA-2048. With the private key, issue a forged manufacturer
 *     CA, then forge device certs for both "host" and "CAM" roles.
 *
 *  3. Build a software CAM that speaks CI+ AKE to any real TV or STB.
 *     Host verifies forged CAM cert (passes against still-trusted root),
 *     completes AKE, derives AKH, starts Content Control session.
 *
 *  4. Point the software CAM at any subscribed satellite/cable feed via
 *     control-word-sharing network. CAM receives CWs (either from a real
 *     smart card elsewhere, or from a compromised one), decrypts the TS,
 *     wraps CWs for CC delivery to the host.
 *
 *  5. Or build a software "host" that connects to real CAMs in the
 *     attacker's possession. The CAM sees a valid CI+ host, hands over
 *     decrypted CWs; the attacker records plaintext pay-TV content for
 *     redistribution.
 *
 *  6. Universal CI+ bypass. Every pay-TV operator using DVB-CI+ loses
 *     the technical enforcement layer, and recovery requires replacing
 *     the CI+ Root (not possible in the installed TV base without
 *     replacing every TV).
 */
