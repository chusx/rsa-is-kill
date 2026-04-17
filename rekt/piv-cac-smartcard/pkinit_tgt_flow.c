/*
 * pkinit_tgt_flow.c
 *
 * DoD CAC / Federal PIV PKINIT flow from smartcard logon to
 * Kerberos TGT, as implemented by the Windows KDC and MIT
 * Kerberos with pkinit preauth.
 *
 * This is the authentication path that converts possession of
 * a PIV card (RSA-2048 key in applet 0xA0...0x3.1) into a
 * domain-admin-equivalent TGT if the certificate has the
 * right EKU (Smartcard Logon, 1.3.6.1.4.1.311.20.2.2).
 *
 * ~8.5 million active CAC+PIV cards across DoD, IC, DHS, VA,
 * Treasury, State, and contractor HSPD-12 implementations.
 */

#include <stdint.h>
#include <string.h>
#include "pkinit.h"

extern const uint8_t DOD_ID_CA_ROOT_PUB[384];   /* DoD Root CA 6 */
extern const uint8_t DOD_EMAIL_CA_ROOT_PUB[384]; /* DoD Email CA 6*/

/* AS-REQ preauth PA-PK-AS-REQ (RFC 4556). The client signs a
 * nonce + DH params with the PIV card's private key. */
struct pa_pk_as_req {
    uint8_t   client_cert[2048]; size_t client_cert_len;
    uint8_t   auth_pack[256];    /* AuthPack DER               */
    uint8_t   auth_pack_sig[256]; /* RSA-SHA256 PKCS#1v15      */
    /* AuthPack contains:
     *   pkAuthenticator:
     *     cusec, ctime (Kerberos timestamp)
     *     nonce
     *     paChecksum (SHA-1 of KDC-REQ-BODY)
     *   clientPublicValue: DH {p,g,y}
     */
};

/* KDC validation (kdc_pkinit.c in MIT Kerberos, or
 * kdcsvc.dll in Windows). This is the code that, if the RSA
 * chain is valid, issues a TGT for the UPN in the cert. */
int kdc_validate_pkinit(const struct pa_pk_as_req *req,
                        const char *requested_principal)
{
    /* (1) Chain client cert to DoD Root CA. */
    if (x509_chain_verify(req->client_cert, req->client_cert_len,
            DOD_ID_CA_ROOT_PUB, sizeof DOD_ID_CA_ROOT_PUB))
        return KDC_CERT_CHAIN;

    /* (2) Check SmartcardLogon EKU and SAN UPN match. */
    char upn[128];
    if (cert_extract_upn(req->client_cert, req->client_cert_len, upn))
        return KDC_NO_UPN;
    if (strcmp(upn, requested_principal))
        return KDC_UPN_MISMATCH;

    /* (3) Verify signature on AuthPack. */
    uint8_t h[32];
    sha256(req->auth_pack, 256, h);
    if (verify_with_cert(req->client_cert, req->client_cert_len,
                         h, req->auth_pack_sig, 256))
        return KDC_SIG;

    /* (4) Timestamp / nonce freshness (5-minute window). */
    if (pkinit_check_ctime(req->auth_pack)) return KDC_CLOCK_SKEW;

    /* (5) CRL / OCSP revocation check against DISA LDAP. */
    if (check_revocation(req->client_cert, req->client_cert_len))
        return KDC_REVOKED;

    /* Issue TGT. The returned AS-REP carries a PA-PK-AS-REP
     * with the KDC's DH public value; session key = DH shared
     * secret. The TGT enc-part is encrypted under the session
     * key; the TGT's authdata carries the S4U PAC. */
    return kdc_issue_tgt(upn);
}

/* =========================================================
 *  The S/MIME path is similar but uses DOD_EMAIL_CA_ROOT:
 *  CAC email-signing cert signs Outlook / Thunderbird mail
 *  with id-smime-ct-authData; recipient validates chain to
 *  the same RSA root.
 * ========================================================= */

/* ---- What the attacker achieves ----------------------------
 *  DOD_ID_CA_ROOT factored (RSA-2048 / 3072):
 *    Mint a cert with SAN = "flag.officer@mil" + SmartcardLogon
 *    EKU; PKINIT gives a TGT for that principal. Full Domain
 *    Admin equivalent in the DoD AD forest. Access to SIPRNet-
 *    bridged systems via cross-realm trust. Personnel records,
 *    operational orders, classified email.
 *
 *  DOD_EMAIL_CA_ROOT factored:
 *    Forge S/MIME as any .mil / .gov address. Signed and
 *    encrypted email from any identity; retroactive decrypt
 *    of archived S/MIME CUI mail.
 *
 *  Per-card RSA-2048 factored:
 *    Impersonate one cleared individual. Lower blast radius but
 *    enough for targeted espionage.
 *
 *  Recovery: DISA re-issues every card + every KDC's trust
 *  store rotated. Card re-issuance at 8.5M scale: years.
 *  Interim: disable PKINIT, fall back to password + OTP for
 *  every cleared user. Degraded assurance across the entire
 *  federal enterprise.
 * --------------------------------------------------------- */
