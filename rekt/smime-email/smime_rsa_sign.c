/*
 * smime_rsa_sign.c
 *
 * S/MIME email signing with RSA — OpenSSL CMS implementation.
 * Source: openssl/apps/smime.c and openssl/apps/cms.c
 * GitHub: https://github.com/openssl/openssl/blob/master/apps/smime.c
 *
 * S/MIME (RFC 8551 / RFC 5652) is the standard for signing and encrypting
 * email in enterprise and government environments. Every S/MIME certificate
 * is RSA-2048 or RSA-4096 issued by an enterprise or public CA.
 *
 * Deployed in:
 *   - Microsoft Outlook (enterprise email, S/MIME gateway)
 *   - Apple Mail (macOS, iOS — supports S/MIME natively)
 *   - US DoD — CAC/PIV certificates include S/MIME email signing
 *   - EU eIDAS qualified email signatures (legally binding in EU)
 *   - Banking / healthcare (HIPAA secure messaging)
 *   - Germany (DE-Mail, BSI guidelines mandate S/MIME)
 *
 * S/MIME CMS SignedData format (RFC 5652):
 *   ContentInfo
 *     SignedData
 *       digestAlgorithms: SHA-256
 *       encapContentInfo: (the email body)
 *       certificates: (signer's RSA-2048 cert + chain)
 *       signerInfos:
 *         SignerInfo
 *           signatureAlgorithm: rsaEncryption (OID 1.2.840.113549.1.1.1)
 *           signature: [256 bytes of RSA-2048 PKCS#1 v1.5]
 *
 * No S/MIME standard exists for ML-DSA or any NIST PQC algorithm.
 * RFC 8551 (S/MIME v4.0, 2019) is RSA-only for signing.
 * The IETF LAMPS WG has PQC S/MIME drafts but no published RFC.
 */

#include <openssl/cms.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

/*
 * smime_sign() — signs an email message with an S/MIME CMS SignedData.
 *
 * This is called by Outlook, Apple Mail, and any S/MIME-aware MUA
 * when the user clicks "Sign" on an outgoing email.
 *
 * Source: openssl/apps/smime.c smime_main() sign path
 */
int smime_sign(BIO *in_msg,   /* email body */
               BIO *out_smime,
               X509 *signer_cert,    /* RSA-2048 email signing certificate */
               EVP_PKEY *signer_key, /* RSA-2048 private key */
               STACK_OF(X509) *chain,
               unsigned long flags)
{
	CMS_ContentInfo *cms = NULL;
	int ret = 0;

	/*
	 * CMS_sign() creates a SignedData structure.
	 * signer_key must be EVP_PKEY_RSA for S/MIME compatibility.
	 *
	 * flags typically include:
	 *   CMS_DETACHED      — detached signature (multipart/signed MIME)
	 *   CMS_BINARY        — treat input as binary
	 *   CMS_USE_KEYID     — use SubjectKeyIdentifier
	 *
	 * The SignerInfo.signatureAlgorithm will be:
	 *   Algorithm: rsaEncryption (1.2.840.113549.1.1.1)
	 *   Parameters: NULL
	 * or with explicit hash:
	 *   Algorithm: sha256WithRSAEncryption (1.2.840.113549.1.1.11)
	 */
	cms = CMS_sign(signer_cert, signer_key, chain, in_msg,
	               flags | CMS_PARTIAL);
	if (!cms) goto err;

	/* Add signing time authenticated attribute (RFC 5652 §11.3) */
	if (!CMS_add1_attr_by_NID(CMS_get0_SignerInfos(cms),
	                           NID_pkcs9_signingTime,
	                           V_ASN1_UTCTIME, NULL, -1))
		goto err;

	/* Finalize — computes SHA-256 digest, signs with RSA private key */
	if (!CMS_final(cms, in_msg, NULL, flags))
		goto err;

	/* Output as SMIME format (or DER) */
	if (!SMIME_write_CMS(out_smime, cms, in_msg, flags))
		goto err;

	ret = 1;
err:
	CMS_ContentInfo_free(cms);
	return ret;
}

/*
 * smime_encrypt() — encrypts email to a recipient's RSA public key.
 *
 * S/MIME encryption uses RSA-OAEP (or older RSA-PKCS1v1.5) to wrap
 * a symmetric content-encryption key (AES-256-CBC). The recipient's
 * RSA public key is taken from their certificate.
 *
 * Source: openssl/apps/smime.c encryption path
 *
 * HNDL risk: intercepted S/MIME-encrypted email can be decrypted once
 * the recipient's RSA-2048 public key is factored. S/MIME provides
 * persistent encryption (unlike ephemeral TLS), so every archived
 * encrypted email is retroactively readable after a CRQC attack.
 */
int smime_encrypt(BIO *in_msg,
                  BIO *out_smime,
                  STACK_OF(X509) *recipients,  /* RSA-2048 recipient certs */
                  const EVP_CIPHER *cipher,    /* EVP_aes_256_cbc() */
                  unsigned long flags)
{
	CMS_ContentInfo *cms = NULL;

	/*
	 * CMS_encrypt() wraps the AES content-encryption key using each
	 * recipient's RSA public key (RSA-OAEP per RFC 8551, or RSAES-PKCS1-v1_5
	 * for legacy S/MIME compatibility mode).
	 *
	 * The RecipientInfo.keyEncryptionAlgorithm will be:
	 *   id-RSAES-OAEP (1.2.840.113549.1.1.7)   -- RFC 8551 requires this
	 * or (legacy):
	 *   rsaEncryption  (1.2.840.113549.1.1.1)   -- still common in practice
	 */
	cms = CMS_encrypt(recipients, in_msg, cipher, flags);
	if (!cms) return 0;

	if (!SMIME_write_CMS(out_smime, cms, in_msg, flags)) {
		CMS_ContentInfo_free(cms);
		return 0;
	}

	CMS_ContentInfo_free(cms);
	return 1;
}

/*
 * DoD and government S/MIME context:
 *
 * The US DoD CAC (Common Access Card) includes an S/MIME email encryption
 * certificate with RSA-2048. Every email sent encrypted with a CAC certificate
 * is potentially retroactively decryptable once a CRQC factors the RSA key.
 *
 * The NSA's CNSA 2.0 suite (2022) mandates ML-KEM and ML-DSA for new systems,
 * but explicitly notes that S/MIME migration timelines have not been published.
 * S/MIME is in use by every cabinet department, all intelligence agencies,
 * and military communications for CUI (Controlled Unclassified Information).
 *
 * Archived S/MIME encrypted email in HNDL scenarios: emails from 2020 encrypted
 * to RSA-2048 government certificates are sitting in archive servers right now.
 */
