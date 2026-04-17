/*
 * ek_credential_activate.c
 *
 * TPM 2.0 RSA Endorsement Key (EK) credential activation
 * (TPM2_ActivateCredential) — the protocol by which a
 * remote attestation server proves to a TPM that it knows
 * the EK's public key without revealing a secret to a
 * MitM. This is the foundation of measured boot attestation
 * (Azure Attestation, GCP Shielded VM, AWS Nitro TPM,
 * Intune device compliance).
 *
 * The EK is RSA-2048 by default (TCG EK Credential Profile,
 * §2.1.5.1); the public portion is the Endorsement Key
 * Certificate, signed by the TPM vendor (Infineon, STMicro,
 * Nuvoton, AMD fTPM, Intel PTT).
 *
 * A factored EK allows an attacker to impersonate the TPM
 * to an attestation server (software-only "TPM emulator"
 * that passes remote attestation as if it were genuine
 * hardware) — defeating Secure Boot, BitLocker, and
 * device-identity trust.
 */

#include <stdint.h>
#include <string.h>
#include "tpm2.h"

extern const uint8_t TPM_VENDOR_EK_CA_PUB[384];

/* EK certificate — stored in NV index 0x01C00002 on every
 * TPM. DER-encoded X.509, RSA-2048. */
struct ek_cert {
    uint8_t  der[2048];
    size_t   der_len;
    /* After parsing: */
    uint8_t  ek_pub_n[256];          /* RSA modulus               */
    uint8_t  ek_pub_e[4];            /* 65537                     */
    char     vendor[32];             /* "Infineon", "STMicro" ... */
    char     tpm_model[32];
};

/* MakeCredential / ActivateCredential protocol (TCG §24):
 *
 *   Attestation Server:
 *     1. Retrieve EK cert from TPM (or from vendor DB).
 *     2. Generate a random credential_blob.
 *     3. MakeCredential: RSA-OAEP encrypt credential_blob
 *        under the EK public key, bound to the AK name.
 *        -> produce (credentialBlob, secret).
 *
 *   TPM (client):
 *     4. TPM2_ActivateCredential(EK, AK, credentialBlob, secret)
 *        -> TPM internally RSA-OAEP decrypts with EK private,
 *           checks AK name binding, returns credential_blob.
 *     5. Client proves possession of credential_blob to server.
 */

struct make_credential_output {
    uint8_t  credential_blob[256];     /* RSA-OAEP ciphertext     */
    uint8_t  secret[256];              /* encrypted by EK pub     */
    uint8_t  ak_name[34];             /* SHA-256 name of the AK  */
};

int attestation_server_make_credential(
        const struct ek_cert *ek,
        const uint8_t *ak_name, size_t ak_name_len,
        struct make_credential_output *out)
{
    /* Verify EK cert against vendor CA. */
    if (x509_chain_verify(ek->der, ek->der_len,
            TPM_VENDOR_EK_CA_PUB, sizeof TPM_VENDOR_EK_CA_PUB))
        return TPM_EK_CHAIN;

    /* Generate 32-byte random credential. */
    uint8_t cred[32];
    csprng(cred, 32);

    /* RSA-OAEP encrypt cred || ak_name under EK public. */
    uint8_t tbs[66];
    memcpy(tbs, cred, 32);
    memcpy(tbs + 32, ak_name, ak_name_len);
    return rsa_oaep_encrypt(ek->ek_pub_n, 256,
                             ek->ek_pub_e, 4,
                             tbs, 32 + ak_name_len,
                             out->credential_blob,
                             &(size_t){256});
}

/* TPM-side ActivateCredential — normally runs inside the
 * TPM's secure boundary. Shown here for protocol clarity. */
int tpm_activate_credential(const uint8_t *ek_priv_d, size_t d_len,
                             const uint8_t *credential_blob,
                             const uint8_t *ak_name,
                             uint8_t *cred_out)
{
    uint8_t decrypted[66];
    size_t dlen = sizeof decrypted;
    rsa_oaep_decrypt(ek_priv_d, d_len,
                     /* EK modulus from NV */ NULL, 256,
                     (uint8_t[]){1,0,1}, 3,
                     credential_blob, 256,
                     decrypted, &dlen);
    /* Check AK name binding. */
    if (memcmp(decrypted + 32, ak_name, 34))
        return TPM_BINDING_FAIL;
    memcpy(cred_out, decrypted, 32);
    return 0;
}

/* ---- Software-TPM-that-passes-attestation attack -----------
 *  1. Extract EK cert from a real TPM (NV index read, or from
 *     the vendor's EK certificate repository — often public).
 *  2. Factor the RSA-2048 modulus.
 *  3. Build a software TPM emulator that holds the recovered
 *     EK private key.
 *  4. The software "TPM" responds to ActivateCredential
 *     exactly as hardware would. The attestation server sees
 *     a valid credential response and marks the device as
 *     "genuine hardware with Secure Boot enabled."
 *  5. The device is actually a VM or bare-metal with no
 *     Secure Boot, no BitLocker, running attacker firmware.
 *     Azure Conditional Access / Intune Compliance / GCP
 *     Shielded VM all report COMPLIANT.
 *
 *  Recovery: TPM vendors issue new EK CAs; every attestation
 *  server updates its trust store. But existing TPMs in the
 *  field cannot be re-EK'd without physical access + clear.
 *  ~2 billion TPMs deployed across enterprise laptops, servers,
 *  and IoT. Fleet refresh = hardware replacement cycle.
 * --------------------------------------------------------- */
