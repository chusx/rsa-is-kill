/*
 * authenticode_rsa_sign.c
 *
 * Windows Authenticode PE/COFF code signing with RSA.
 * Excerpted / adapted from osslsigncode (mtrojnar/osslsigncode on GitHub)
 * Source: https://github.com/mtrojnar/osslsigncode/blob/master/osslsigncode.c
 *
 * Authenticode is the Microsoft code signing standard for:
 *   - Windows kernel drivers (mandatory for 64-bit Windows 10+)
 *   - Windows executables and DLLs (shown in SmartScreen UI)
 *   - PowerShell scripts (with execution policy enforcement)
 *   - .cab, .msi, .msix, .appx packages
 *   - Windows Update packages
 *   - EFI boot applications
 *
 * The Microsoft Trusted Root Program requires RSA-2048 minimum for
 * code signing certificates. ECDSA is NOT accepted in the Microsoft
 * root program for code signing (as of 2025). No PQC OID has been
 * allocated for Authenticode. SB/Driver signing portal (WHCP) accepts
 * only RSA-2048/4096 submissions.
 *
 * Format: PKCS#7 SignedData embedded in the PE file's
 * Certificate Table (IMAGE_DIRECTORY_ENTRY_SECURITY).
 */

#include <openssl/pkcs7.h>
#include <openssl/cms.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/objects.h>

/* Authenticode OIDs */
#define SPC_INDIRECT_DATA_OBJID     "1.3.6.1.4.1.311.2.1.4"
#define SPC_PE_IMAGE_DATA_OBJID     "1.3.6.1.4.1.311.2.1.15"
#define MS_OPUS_INFO_OBJID          "1.3.6.1.4.1.311.2.1.12"
#define SPC_STATEMENT_TYPE_OBJID    "1.3.6.1.4.1.311.2.1.11"
#define INDIVIDUAL_CODE_SIGNING_OID "1.3.6.1.4.1.311.2.1.21"

/*
 * pe_calc_digest() — compute the Authenticode hash of a PE image.
 *
 * The Authenticode hash covers the PE image with the checksum field
 * and Certificate Table zeroed out. This is what gets signed.
 * From osslsigncode pe.c / helper.c
 */
static int pe_calc_digest(char *indata, uint32_t filesize,
                          const EVP_MD *md, uint8_t *mdbuf, int *mdlen)
{
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	/* ... skip PE header, zero checksum, skip cert table, hash rest ... */
	EVP_DigestInit(mdctx, md);
	/* Hash PE contents excluding checksum and Certificate Table pointer */
	EVP_DigestUpdate(mdctx, indata, pe_header_offset + 88);    /* up to checksum */
	EVP_DigestUpdate(mdctx, indata + pe_header_offset + 92,    /* skip checksum */
	                 certdir_offset - (pe_header_offset + 92));
	/* ... hash rest of file ... */
	EVP_DigestFinal(mdctx, mdbuf, (unsigned int*)mdlen);
	EVP_MD_CTX_free(mdctx);
	return 0;
}

/*
 * sign_pe_image() — the main Authenticode signing function.
 *
 * Creates PKCS#7 SignedData containing:
 *   - SpcIndirectDataContent (the PE Authenticode hash)
 *   - SignerInfo with RSA PKCS#1 v1.5 signature
 *   - Signing certificate (RSA-2048 code signing cert)
 *   - Timestamp countersignature (RFC 3161)
 *
 * Source: osslsigncode osslsigncode.c sign_pe_file()
 */
static PKCS7 *sign_pe_image(char *indata, uint32_t filesize,
                             EVP_PKEY *sign_key,  /* RSA-2048 private key */
                             X509 *sign_cert,
                             STACK_OF(X509) *chain,
                             const EVP_MD *md)
{
	PKCS7 *p7 = NULL;
	PKCS7_SIGNER_INFO *si;
	unsigned char mdbuf[EVP_MAX_MD_SIZE];
	int mdlen;
	ASN1_STRING *astr;
	BIO *p7bio;

	/* Compute the Authenticode hash of the PE image */
	pe_calc_digest(indata, filesize, md, mdbuf, &mdlen);

	/* Build SpcIndirectDataContent */
	/* ... encode SpcPeImageData + AlgorithmIdentifier + digest ... */

	/* Create PKCS7 SignedData */
	p7 = PKCS7_new();
	PKCS7_set_type(p7, NID_pkcs7_signed);
	PKCS7_content_new(p7, NID_pkcs7_data);

	/*
	 * Add signer — RSA-2048 code signing certificate.
	 * PKCS7_add_signature() selects the digest algorithm and creates
	 * a SignerInfo. The RSA private key signs the authenticated attributes
	 * (which include the Authenticode hash of the PE image).
	 *
	 * EVP_PKEY_RSA is required here — the Microsoft root program does not
	 * accept ECDSA-signed code signing certs in the trusted root store
	 * for Authenticode (as of 2025). RSA is the only supported algorithm.
	 */
	si = PKCS7_add_signature(p7, sign_cert, sign_key, md);
	if (!si) return NULL;

	/* Add the SPC Statement Type authenticated attribute */
	PKCS7_add_signed_attribute(si, OBJ_txt2nid(SPC_STATEMENT_TYPE_OBJID),
	                           V_ASN1_SEQUENCE, astr);

	/* Add certificate chain */
	PKCS7_add_certificate(p7, sign_cert);
	for (int i = 0; i < sk_X509_num(chain); i++)
		PKCS7_add_certificate(p7, sk_X509_value(chain, i));

	/* Sign — RSA_sign() is called internally with the private key */
	p7bio = PKCS7_dataInit(p7, NULL);
	/* write SpcIndirectDataContent to p7bio */
	PKCS7_dataFinal(p7, p7bio);
	BIO_free(p7bio);

	return p7;
}

/*
 * Windows Kernel Driver Signing (WHCP)
 *
 * Starting with Windows 10 1607, all kernel-mode drivers must be submitted
 * to the Microsoft Hardware Dev Center (WHCP / Sysdev) for signing.
 * Microsoft countersigns with their Production PCA 2011 certificate (RSA-2048).
 *
 * The full chain:
 *   Microsoft Root Certificate Authority 2010 (RSA-2048, 10-year)
 *     Microsoft Code Signing PCA 2011 (RSA-2048)
 *       Microsoft Windows Hardware Compatibility Publisher (RSA-2048)
 *         [your driver] (RSA-2048 signature from the WHCP portal)
 *
 * A CRQC factoring the Microsoft Code Signing PCA 2011 RSA key can issue
 * WHCP-equivalent signatures for any driver. Windows kernel will load it
 * without any prompt or warning. Persistent kernel-mode rootkit with full
 * trust from Windows security infrastructure.
 */
