/*
 * kdc_pkinit_preauth.c
 *
 * KDC-side PKINIT pre-authentication handler (RFC 4556). Sits in
 * front of the RSA verify/unwrap primitives in `pkinit_rsa.c` and is
 * the code path triggered whenever a Windows workstation with a PIV
 * card / YubiKey, or a Linux host with sssd-configured certificate
 * login, does a smart-card Kerberos logon.
 *
 * Deployed in:
 *   - Every Active Directory domain controller (Windows Server
 *     2016/2019/2022/2025 Kerberos KDC)
 *   - MIT Kerberos krb5kdc in federal / DoD / IC environments
 *     (CAC/PIV smart-card logon)
 *   - Heimdal KDC on macOS Server / Apple Enterprise Connect
 *   - FreeIPA / Red Hat Identity Management domain controllers
 */

#include <krb5.h>
#include <string.h>
#include "pkinit.h"
#include "pkinit_rsa.h"


struct pkinit_kdc_state {
    krb5_context         ctx;
    krb5_principal       kdc_principal;
    X509               *kdc_cert;           /* KDC auth cert, RSA-2048+ */
    EVP_PKEY           *kdc_private;
    X509_STORE         *client_trust_roots; /* Enterprise Root CAs (AD: NTAuth store) */
    int                 require_freshness;  /* Windows: MS-KILE freshness post-2022 */
};


/* Triggered from the KDC's AS_REQ dispatcher when PA-PK-AS-REQ
 * padata is present. */
krb5_error_code
pkinit_kdc_handle_asreq(struct pkinit_kdc_state *s,
                         krb5_kdc_req *asreq,
                         krb5_pa_data *pa_pk_as_req,
                         krb5_pa_data **out_pa_pk_as_rep)
{
    /* 1. Parse PKAuthenticator + client signed AuthPack.  AuthPack is
     *    CMS SignedData; client's RSA signature covers the KDC
     *    principal name + a fresh nonce + (new) freshness token. */
    krb5_pk_authenticator auth;
    krb5_data             client_public_value;
    X509                 *client_cert;
    krb5_data             signed_auth_pack;
    if (pkinit_parse_as_req(pa_pk_as_req, &auth,
                             &client_public_value,
                             &client_cert,
                             &signed_auth_pack) != 0)
        return KRB5KDC_ERR_PREAUTH_FAILED;

    /* 2. Verify client cert chain under the enterprise trust roots
     *    (Windows NTAuth store / MIT pkinit_anchors / sssd
     *    pkinit_ca_dir).  EKU must include id-pkinit-KPClientAuth
     *    (1.3.6.1.5.2.3.4) or the legacy Smartcard Logon EKU
     *    (1.3.6.1.4.1.311.20.2.2). */
    if (pkinit_verify_client_cert_chain(s, client_cert) != 0)
        return KRB5KDC_ERR_CLIENT_NOT_TRUSTED;

    /* 3. Verify the CMS RSA signature on AuthPack.  This is the hot
     *    path — `pkinit_rsa_verify_signed_auth_pack`. */
    if (pkinit_rsa_verify_signed_auth_pack(
            client_cert, &signed_auth_pack) != 0)
        return KRB5KDC_ERR_PREAUTH_FAILED;

    /* 4. Bind cert → principal. AD does this via SID mapping
     *    encoded in the cert (MS-KILE strong-mapping post-2023
     *    KB5014754 hard-enforcement); MIT does it via
     *    pkinit_cert_matching rules (SAN UPN or subject DN). */
    krb5_principal mapped_principal;
    if (pkinit_match_cert_to_principal(s, client_cert, asreq->client,
                                         &mapped_principal) != 0)
        return KRB5KDC_ERR_CERTIFICATE_MISMATCH;

    /* 5. Freshness check (Windows 2022+, RFC 8070). The client's
     *    AuthPack must include a freshness token the KDC issued in
     *    a prior AS-REP; prevents pre-computed replayable PKINIT
     *    blobs against a compromised workstation clock. */
    if (s->require_freshness &&
        pkinit_verify_freshness_token(s, &auth) != 0)
        return KRB5KDC_ERR_PREAUTH_FAILED;

    /* 6. Derive the reply-key:
     *    - Old DH path: ephemeral DH contributory key → PRF
     *    - MODP mode (rare these days)
     *    - RSA key-transport: KDC generates random reply-key, encrypts
     *      with client's RSA public key (RSA-OAEP).  This is the
     *      primitive that dies under a factoring break. */
    krb5_keyblock reply_key;
    if (pkinit_derive_reply_key_rsa(
            s, client_cert, &client_public_value, &reply_key) != 0)
        return KRB5KDC_ERR_PREAUTH_FAILED;

    /* 7. Emit KDC's counter-signed PA-PK-AS-REP (CMS SignedData over
     *    the reply-key wrap + a DHRepInfo structure).  KDC signs with
     *    its own RSA private key — client later verifies against the
     *    domain's NTAuth store. */
    return pkinit_build_as_rep(s, asreq, mapped_principal,
                                &reply_key, out_pa_pk_as_rep);
}


/* Breakage:
 * The factoring primitive against the Enterprise Root CA (the one
 * anchored in NTAuth) is catastrophic for any AD forest: an attacker
 * mints a smart-card cert mapping to Domain Admin, walks through
 * PKINIT, receives a TGT, and gets unconstrained delegation across
 * the forest. This is the cryptographic equivalent of the "PetitPotam +
 * ESC8" chain but skipping the whole exploit stack — just forge and
 * sign. Federal/DoD PIV environments have the same structure
 * (DoD Root CA 3/6 + NIPRNET-wide NTAuth store).
 */
