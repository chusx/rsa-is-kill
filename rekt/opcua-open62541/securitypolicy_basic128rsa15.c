/* Source: open62541/open62541 plugins/crypto/openssl/securitypolicy_basic128rsa15.c
 * OPC-UA (IEC 62541) is the dominant communication standard for industrial
 * control systems (ICS), SCADA, and factory automation.
 * The Basic128Rsa15 security policy uses:
 *   - RSA-PKCS1-v1.5 encryption (128-bit AES session key wrapped with RSA)
 *   - RSA-PKCS1-v1.5 + SHA-1 for message signing
 * Both RSA-PKCS1-v1.5 and SHA-1 are classically broken.
 * The OPC-UA specification (Part 7) mandates this policy for backward compatibility.
 * No PQC security policy exists in the OPC-UA specification.
 */

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. */

#include <open62541/plugin/securitypolicy_default.h>
#include <open62541/util.h>

#if defined(UA_ENABLE_ENCRYPTION_OPENSSL) || defined(UA_ENABLE_ENCRYPTION_LIBRESSL)

#include "securitypolicy_common.h"
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#define UA_SHA1_LENGTH                                               20
#define UA_SECURITYPOLICY_BASIC128RSA15_RSAPADDING_LEN               11
#define UA_SECURITYPOLICY_BASIC128RSA15_SYM_ENCRYPTION_KEY_LENGTH    16
#define UA_SECURITYPOLICY_BASIC128RSA15_SYM_ENCRYPTION_BLOCK_SIZE    16
#define UA_SECURITYPOLICY_BASIC128RSA15_SYM_SIGNING_KEY_LENGTH       16

/* Verify a message signature using RSA-PKCS1-v1.5 + SHA-1 */
static UA_StatusCode
asym_verify_sp_basic128rsa15(UA_SecurityPolicy *securityPolicy,
                             void *channelContext,
                             const UA_ByteString *message,
                             const UA_ByteString *signature) {
    if(message == NULL || signature == NULL || channelContext == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    /* RSA-PKCS1-v1.5 with SHA-1 — broken by quantum (Shor) and classically weak */
    return UA_OpenSSL_RSA_PKCS1_V15_SHA1_Verify(message, cc->remoteCertificateX509,
                                                signature);
}

/* Sign a message using RSA-PKCS1-v1.5 + SHA-1 */
static UA_StatusCode
asym_sign_sp_basic128rsa15(UA_SecurityPolicy *securityPolicy,
                           void *channelContext,
                           const UA_ByteString *message,
                           UA_ByteString *signature) {
    if(channelContext == NULL || message == NULL || signature == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    return UA_Openssl_RSA_PKCS1_V15_SHA1_Sign(message, pc->localPrivateKey, signature);
}

/* Decrypt session key material using RSA-PKCS1-v1.5 (textbook vulnerable) */
static UA_StatusCode
asym_decrypt_sp_basic128rsa15(UA_SecurityPolicy *securityPolicy,
                              void *channelContext, UA_ByteString *data) {
    return UA_Openssl_RSA_PKCS1_V15_Decrypt(data, pc->localPrivateKey);
}

/* Encrypt session key material using RSA-PKCS1-v1.5 */
static UA_StatusCode
asym_encrypt_sp_basic128rsa15(UA_SecurityPolicy *securityPolicy,
                              void *channelContext, UA_ByteString *data) {
    return UA_Openssl_RSA_PKCS1_V15_Encrypt(data,
                                            UA_SECURITYPOLICY_BASIC128RSA15_RSAPADDING_LEN,
                                            cc->remoteCertificateX509);
}

/* Policy registration — note the deprecation warning is printed at runtime */
UA_StatusCode
UA_SecurityPolicy_Basic128Rsa15(UA_SecurityPolicy *policy, ...) {
    /* ... */
    UA_LOG_WARNING(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                   "There are known attacks that break the encryption.");
    sp->certificateTypeId = UA_NS0ID(RSAMINAPPLICATIONCERTIFICATETYPE);
    sp->policyType = UA_SECURITYPOLICYTYPE_RSA;

    asymSig->uri = UA_STRING("http://www.w3.org/2000/09/xmldsig#rsa-sha1\0");
    asymSig->sign = UA_AsySig_Basic128Rsa15_Sign;

    asymEnc->uri = UA_STRING("http://www.w3.org/2001/04/xmlenc#rsa-1_5\0");
    asymEnc->encrypt = UA_AsymEn_Basic128Rsa15_Encrypt;
}
