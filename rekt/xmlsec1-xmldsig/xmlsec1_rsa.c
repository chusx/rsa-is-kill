/*
 * xmlsec1_rsa.c
 *
 * XML Security Library (xmlsec1) — RSA in XML Digital Signatures.
 * Repository: https://github.com/lsh123/xmlsec (also: aleksey.com/xmlsec/)
 * Source: src/openssl/signatures.c, src/openssl/asymkeys.c
 *
 * xmlsec1 is the C library for W3C XML Digital Signatures (XMLDSig) and
 * XML Encryption. The Java equivalent is Apache Santuario (see apache-santuario/).
 * xmlsec1 is used in:
 *
 *   - SAML implementations in C/Python/Ruby/PHP (mod_auth_mellon on Apache)
 *   - mod_auth_mellon (Apache HTTPD SAML SP — used by thousands of universities)
 *   - SimpleSAMLphp (the most common PHP SAML implementation)
 *   - lasso (C library for SAML, used in Python/Perl enterprise SSO)
 *   - eID-based electronic government signatures (EU eIDAS):
 *       - Belgian eID (fedict/eid-client)
 *       - Estonian X-Road (government data exchange, 1000+ organizations)
 *       - Finnish Suomi.fi (national digital identity)
 *       - European PEPPOL (Pan-European Public Procurement OnLine)
 *
 * Estonian X-Road is particularly notable: it uses xmlsec1-based XMLDSig for
 * all inter-agency data exchange in Estonia (health, finance, law enforcement,
 * tax authority). Estonia has a fully digital government built on X-Road.
 *
 * W3C XMLDSig RSA algorithm URIs implemented by xmlsec1:
 *   http://www.w3.org/2000/09/xmldsig#rsa-sha1           (SHA-1, legacy, still deployed)
 *   http://www.w3.org/2001/04/xmldsig-more#rsa-sha256     (SHA-256, current)
 *   http://www.w3.org/2001/04/xmldsig-more#rsa-sha512     (SHA-512)
 */

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/crypto.h>
#include <xmlsec/openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

/*
 * xmlSecOpenSSLKeyDataRsaId — the xmlsec key data type for RSA keys.
 * Source: xmlsec/src/openssl/asymkeys.c
 *
 * This is the "RSA" key type in xmlsec1's key management. RSA-2048 and
 * RSA-4096 keys are loaded from PEM files, PKCS#12, or X.509 certificates.
 * There is no "ML-DSA" or "ML-KEM" key data type in xmlsec1.
 */
xmlSecKeyDataId xmlSecOpenSSLKeyDataRsaId;

/*
 * xmlSecOpenSSLTransformRsaSha256Id — RSA-SHA256 transform.
 * The "transform" is the xmlsec1 object for signing/verifying with RSA-SHA256.
 *
 * Algorithm URI: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
 *
 * This is used in every SAML assertion signed with RSA, every eIDAS XMLDSig,
 * every X-Road message signature.
 */
xmlSecTransformId xmlSecOpenSSLTransformRsaSha256Id;

/*
 * xmlSecOpenSSLTransformRsaPkcs1Id — RSA-OAEP key transport transform.
 * Algorithm URI: http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p
 * Used in XML Encryption to wrap the per-document AES key with RSA.
 */
xmlSecTransformId xmlSecOpenSSLTransformRsaOaepId;

/*
 * xmlSecOpenSSLRsaSign() — sign an XML document using RSA.
 * Source: xmlsec/src/openssl/signatures.c xmlSecOpenSSLRsaSign()
 *
 * Called by xmlSecDSigCtxSign() when the signature algorithm is RSA-SHA256.
 * The input is the canonicalized ds:SignedInfo element; the output is the
 * base64-encoded RSA signature in ds:SignatureValue.
 */
static int
xmlSecOpenSSLRsaSign(xmlSecTransformPtr transform,
                     const xmlSecByte *in, xmlSecSize inSize,
                     xmlSecByte *out, xmlSecSize *outSize)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY *pkey;
    const EVP_MD *md;
    size_t sigLen;
    int ret = -1;

    /* Extract the RSA private key from the transform context */
    pkey = xmlSecOpenSSLKeyDataRsaGetKey(transform->data, 0 /* private */);
    if (!pkey || EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
        xmlSecError(XMLSEC_ERRORS_HERE, NULL,
                    "xmlSecOpenSSLKeyDataRsaGetKey",
                    XMLSEC_ERRORS_R_INVALID_KEY_DATA,
                    XMLSEC_ERRORS_NO_MESSAGE);
        goto done;
    }

    /* Determine hash algorithm from transform (SHA-256, SHA-512, etc.) */
    md = EVP_sha256();  /* for rsa-sha256 transform */

    mctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mctx, &pctx, md, NULL, pkey);

    /* Apply PKCS#1 v1.5 padding (or PSS for rsa-pss transform) */
    EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING);

    /* Sign the SignedInfo canonical bytes with the RSA private key */
    EVP_DigestSign(mctx, NULL, &sigLen, in, inSize);
    EVP_DigestSign(mctx, out, &sigLen, in, inSize);
    *outSize = sigLen;

    ret = 0;
done:
    EVP_MD_CTX_free(mctx);
    return ret;
}

/*
 * Estonia X-Road XML signing using xmlsec1.
 *
 * X-Road (Riigi Infosüsteemi Amet, Estonian Information System Authority)
 * is the backbone of Estonian e-government: tax authority, health records,
 * business register, police, courts, social services, municipalities.
 * Over 1000 organizations exchange data over X-Road daily.
 *
 * Every X-Road SOAP message is signed with XMLDSig. The signing certificate
 * is an RSA-2048 X.509 certificate issued by SK ID Solutions AS (the Estonian
 * national ID CA) or by the organization's own CA.
 *
 * The X-Road security server uses xmlsec1 for all XML signature operations:
 */
int xroad_sign_message(xmlDocPtr soap_doc, EVP_PKEY *org_signing_key,
                       X509 *org_signing_cert)
{
    xmlSecDSigCtxPtr dsig_ctx = NULL;
    xmlNodePtr signature_node;
    int ret = -1;

    /* Create xmlsec signature context */
    dsig_ctx = xmlSecDSigCtxCreate(NULL);
    if (!dsig_ctx) goto done;

    /* Set the RSA-2048 signing key */
    dsig_ctx->signKey = xmlSecOpenSSLKeyFromEVP(org_signing_key);
    xmlSecKeySetName(dsig_ctx->signKey, "org-signing-key");

    /* Set certificate for KeyInfo (validators need the cert to verify) */
    xmlSecOpenSSLKeyDataX509AdoptCert(
        xmlSecKeyEnsureData(dsig_ctx->signKey, xmlSecOpenSSLKeyDataX509Id),
        org_signing_cert);

    /* Find the ds:Signature node inserted in the SOAP envelope */
    signature_node = xmlSecFindNode(xmlDocGetRootElement(soap_doc),
                                    xmlSecNodeSignature, xmlSecDSigNs);

    /* Sign — calls xmlSecOpenSSLRsaSign() above */
    /* Inserts base64(SHA256withRSA(canonicalized_SignedInfo)) into ds:SignatureValue */
    ret = xmlSecDSigCtxSign(dsig_ctx, signature_node);

done:
    xmlSecDSigCtxDestroy(dsig_ctx);
    return ret;
}
