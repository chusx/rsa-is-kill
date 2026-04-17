/*
 * attestation_flow.c
 *
 * How the RSA-2048 Endorsement Key manufactured into every TPM 2.0
 * (`tpm2_rsa_endorsement_key.c`) is actually driven during remote
 * attestation. This is the path that:
 *
 *   - Windows 11 Attestation Identity Key provisioning takes.
 *   - Azure Attestation, AWS NitroTPM, Google Cloud vTPM, and
 *     Azure Confidential VM TPM rely on.
 *   - Every Microsoft Defender for Endpoint "device health
 *     attestation" (DHA) call goes through.
 *   - Strongswan IKEv2 + TNC, wpa_supplicant with TPM-backed
 *     EAP-TLS, and disk-encryption (BitLocker, LUKS-tpm2, sd-boot
 *     systemd-cryptsetup) use for secret unseal under PCR policy.
 *
 * TPMs ship with an RSA-2048 EK burned by the TPM vendor (Infineon,
 * STMicro, Nuvoton) whose cert chains to the vendor Root CA
 * distributed by the TCG and shipped in every major OS's trust
 * store.  Losing the EK's RSA security means the entire "did this
 * attestation actually come from a genuine TPM?" question becomes
 * unanswerable.
 */

#include <stdio.h>
#include <string.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tpm2_types.h>

/* Step 1: Read the EK public + cert from NV indices 0x1C00002 /
 *         0x1C0000A (per TCG EK Credential Profile). */
TPM2B_PUBLIC *
read_ek_public(ESYS_CONTEXT *ectx)
{
    TPM2B_PUBLIC *ekpub = NULL;
    ESYS_TR ek_handle = ESYS_TR_NONE;

    /* CreatePrimary under Endorsement hierarchy, TPM2_RSA_EK_TEMPLATE */
    TPM2B_SENSITIVE_CREATE inSensitive = {0};
    TPM2B_PUBLIC inPublic = rsa2048_ek_template();
    TPM2B_DATA outsideInfo = {0};
    TPML_PCR_SELECTION creationPCR = {0};

    Esys_CreatePrimary(ectx, ESYS_TR_RH_ENDORSEMENT,
                       ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                       &inSensitive, &inPublic, &outsideInfo,
                       &creationPCR, &ek_handle, &ekpub,
                       NULL, NULL, NULL);
    return ekpub;
}

/* Step 2: Attestation service (Azure Attestation, AWS KMS custom key
 *         store, local enterprise CA) issues a TPM2 MakeCredential
 *         challenge — an AES-wrapped secret encrypted to the EK's
 *         RSA pubkey. */
void
issue_mcred_challenge(TPM2B_PUBLIC *ekpub, TPM2B_PUBLIC *aik_pub,
                      uint8_t challenge_secret[16],
                      /* out */ TPM2B_ID_OBJECT *credBlob,
                      /* out */ TPM2B_ENCRYPTED_SECRET *secret)
{
    /* RSA-OAEP encrypt of `challenge_secret` under ekpub; this
     * is the step that silently fails open under a factoring
     * attack. */
    tpm2_makecredential(ekpub, aik_pub, challenge_secret,
                        credBlob, secret);
}

/* Step 3: TPM-side ActivateCredential — only a TPM in possession of
 *         the EK private key can unwrap the secret. Whoever returns
 *         the correct secret has proven (a) a genuine TPM, (b) that
 *         this TPM owns the AIK claimed.  */
int
activate_credential(ESYS_CONTEXT *ectx, ESYS_TR aik_handle,
                    ESYS_TR ek_handle,
                    TPM2B_ID_OBJECT *credBlob,
                    TPM2B_ENCRYPTED_SECRET *secret,
                    TPM2B_DIGEST **cert_info)
{
    return Esys_ActivateCredential(ectx, aik_handle, ek_handle,
                                   ESYS_TR_PASSWORD, ESYS_TR_PASSWORD,
                                   ESYS_TR_NONE,
                                   credBlob, secret, cert_info);
}

/* Step 4: Service-side verifier: receives the unwrapped secret,
 *         compares against its own generated value. Success → issues
 *         an AIK cert (RSA-2048 or P-256) that becomes the long-lived
 *         attestation identity. */

/* Step 5: PCR quote. AIK signs a Quote structure containing
 *         TPML_PCR_SELECTION + TPML_DIGEST. The verifier checks
 *         (a) the quote signature against the AIK pubkey from step 4;
 *         (b) the PCR digests against a known-good whitelist
 *         (e.g. Azure-certified boot measurements for a Gen2 VM). */

int
quote_pcrs(ESYS_CONTEXT *ectx, ESYS_TR aik_handle,
           TPM2B_ATTEST **out_quote, TPMT_SIGNATURE **out_sig)
{
    TPM2B_DATA qualifying = { .size = 20 };
    gen_nonce(qualifying.buffer, 20);
    TPMT_SIG_SCHEME scheme = { .scheme = TPM2_ALG_RSAPSS,
                                .details.rsapss.hashAlg = TPM2_ALG_SHA256 };
    TPML_PCR_SELECTION pcr = sel_pcrs(0,1,2,3,4,5,6,7,8,9,10,11);
    return Esys_Quote(ectx, aik_handle, ESYS_TR_PASSWORD,
                      ESYS_TR_NONE, ESYS_TR_NONE,
                      &qualifying, &scheme, &pcr,
                      out_quote, out_sig);
}

/* ---- Breakage ----------------------------------------------------
 *
 * The EK RSA key is the single factor anchoring "this is a genuine
 * TPM".  Everything downstream — AIK issuance, BitLocker auto-unlock
 * under PCR policy, Azure Attestation's guest-attestation VM trust,
 * AWS NitroTPM's confidential-VM attestation, Defender DHA, Google
 * Shielded VMs' vTPM attestation — trusts the EK cert chain up to
 * the TPM vendor root CA.
 *
 * A factoring attack against:
 *   - A TPM vendor Root CA (Infineon, STMicro, Nuvoton, NationZ):
 *     attacker mints an EK cert for a software-emulated TPM
 *     (swtpm / ibmswtpm) that every attestation service on the
 *     planet accepts as genuine hardware. Confidential-VM
 *     attestation collapses — the attacker runs a regular VM,
 *     answers challenges with a forged EK, and satisfies "proof
 *     this ran inside a real enclave".
 *   - An individual TPM's EK: one compromised laptop silently
 *     clones its device-health attestation, bypassing Intune
 *     conditional access for that user.
 *
 * EK is not rotatable — it's burned at silicon manufacture.
 * Recovery = physical replacement of the TPM chip or motherboard.
 */
