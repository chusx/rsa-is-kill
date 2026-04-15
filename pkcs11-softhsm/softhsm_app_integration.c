/*
 * softhsm_app_integration.c
 *
 * How real applications invoke SoftHSMv2 through the PKCS#11 v3 API.
 * Wraps the RSA primitive entry points in `pkcs11_no_pqc.c` and shows
 * end-to-end integration: C_Initialize → slot/token open → login →
 * C_SignInit/C_Sign → C_Finalize.
 *
 * SoftHSMv2 is the OpenDNSSEC-reference PKCS#11 implementation,
 * heavily used as a dev/test stand-in for "real" HSMs and — notably —
 * as the production HSM in smaller deployments that can't afford
 * Luna / Utimaco / CloudHSM:
 *   - DNSSEC registry operators' lab + secondary-site configurations
 *     (Knot DNS, BIND, NSD all link against libsofthsm2 for RR
 *     signing in reduced-redundancy sites)
 *   - Kubernetes cert-manager + Vault PKI tenants that ask for
 *     "some kind of key isolation" without the hardware budget
 *   - Lets Encrypt Pebble + Boulder dev/staging infrastructure
 *   - Test environments for banks/telcos transitioning to real HSMs
 *   - EJBCA test CAs, Dogtag Certificate System lab configs
 *
 * The same PKCS#11 entry points are what Thales Luna, Utimaco,
 * Entrust nShield, AWS CloudHSM, Google Cloud HSM, YubiHSM 2, and
 * Fortanix DSM expose — so the integration shape here is identical
 * to production hardware HSMs.
 */

#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include "pkcs11.h"


static CK_FUNCTION_LIST_PTR F;


int
pkcs11_boot(const char *lib_path)
{
    void *h = dlopen(lib_path, RTLD_NOW);
    if (!h) return -1;

    CK_RV (*C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR) =
        dlsym(h, "C_GetFunctionList");
    if (C_GetFunctionList(&F) != CKR_OK) return -1;

    CK_C_INITIALIZE_ARGS args = {
        .flags = CKF_OS_LOCKING_OK
    };
    return F->C_Initialize(&args) == CKR_OK ? 0 : -1;
}


int
pkcs11_sign_blob(CK_SLOT_ID slot, const char *user_pin,
                  const char *key_label,
                  const unsigned char *msg, size_t msg_len,
                  unsigned char *sig, size_t *sig_len)
{
    CK_SESSION_HANDLE h;
    if (F->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL, &h)
        != CKR_OK) return -1;

    if (F->C_Login(h, CKU_USER, (CK_UTF8CHAR *)user_pin,
                    strlen(user_pin)) != CKR_OK) return -1;

    /* Find the RSA private key by label. */
    CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
    CK_KEY_TYPE     kt  = CKK_RSA;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &cls, sizeof cls },
        { CKA_KEY_TYPE, &kt,  sizeof kt  },
        { CKA_LABEL,    (void *)key_label, strlen(key_label) },
    };
    CK_OBJECT_HANDLE priv;
    CK_ULONG found;
    F->C_FindObjectsInit(h, tmpl, 3);
    F->C_FindObjects(h, &priv, 1, &found);
    F->C_FindObjectsFinal(h);
    if (found != 1) return -1;

    /* RSA-PSS with SHA-256 / MGF1-SHA-256 / salt=32. */
    CK_RSA_PKCS_PSS_PARAMS pss = {
        .hashAlg    = CKM_SHA256,
        .mgf        = CKG_MGF1_SHA256,
        .sLen       = 32,
    };
    CK_MECHANISM mech = {
        .mechanism = CKM_SHA256_RSA_PKCS_PSS,
        .pParameter = &pss, .ulParameterLen = sizeof pss,
    };
    F->C_SignInit(h, &mech, priv);

    CK_ULONG out = *sig_len;
    CK_RV rv = F->C_Sign(h, (CK_BYTE_PTR)msg, msg_len,
                          (CK_BYTE_PTR)sig, &out);
    *sig_len = out;

    F->C_Logout(h);
    F->C_CloseSession(h);
    return rv == CKR_OK ? 0 : -1;
}


/* Same function shape unlocks every HSM in the field — only the
 * lib_path and slot configuration differ:
 *   /usr/lib64/pkcs11/libsofthsm2.so
 *   /usr/safenet/lunaclient/lib/libCryptoki2_64.so
 *   /opt/utimaco/PKCS11/x86_64/libcs_pkcs11_R3.so
 *   /opt/cloudhsm/lib/libcloudhsm_pkcs11.so
 *   /usr/local/lib/libfortanix_pkcs11.so
 *   /Applications/YubiKey Manager.app/Contents/MacOS/../lib/ykcs11.dylib
 */


/* ---- Breakage ----
 *
 * PKCS#11 is the *only* universal cryptographic API for HSMs. Every
 * RSA-signing application in production — CAs, TSAs, DNSSEC signers,
 * code-signing pipelines, EMV issuance, TLS WAF termination fleets —
 * enters the RSA math path through calls shaped exactly like this.
 *
 * A factoring attack is transparent to the PKCS#11 API: the private
 * key can stay safely inside the HSM, producing valid signatures
 * forever, and an attacker simply forges the same signatures
 * off-card. PKCS#11 was designed to protect against extraction, not
 * against mathematical equivalence — every HSM in the world
 * immediately loses its security property under a factoring break,
 * regardless of how well-protected the physical key material is.
 */
