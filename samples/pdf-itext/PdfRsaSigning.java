/*
 * Source: iText / Apache PDFBox pattern
 * Reference: iText Digital Signatures for PDF (Bruno Lowagie, 2013)
 *            https://itextpdf.com/sites/default/files/2018-12/digitalsignatures20130304.pdf
 * Libraries: iText (AGPL / Commercial), Apache PDFBox (Apache-2.0)
 *
 * Relevant excerpt: RSA is the default and overwhelmingly most common
 * algorithm for PDF digital signatures.
 *
 * PDF digital signatures (ISO 32000-2) are used for:
 *   - Legal contracts and court documents
 *   - Government forms (tax returns, permits, FOIA)
 *   - Healthcare records and prescriptions
 *   - Financial agreements
 *   - eIDAS-compliant signatures across the EU
 *
 * RSA is specified in:
 *   - PDF 1.3+: RSA up to 1024 bits
 *   - PDF 1.5+: RSA up to 2048 bits
 *   - PDF 1.7+: RSA up to 4096 bits
 *
 * A forged RSA signature on a PDF is legally indistinguishable from
 * a genuine one.  A CRQC could retroactively forge any signed PDF ever
 * created — contracts, wills, court orders, medical records.
 *
 * NOTE: iText 9.5 (2025) added experimental ML-DSA support, and the
 * PDF Association and Adobe exchanged the first ML-DSA-signed PDF in
 * May 2025.  But no production CA issues PQC PDF signing certs yet,
 * and no PDF reader outside labs validates ML-DSA signatures.
 */

import com.itextpdf.kernel.pdf.*;
import com.itextpdf.signatures.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.*;
import java.security.cert.*;

public class PdfRsaSigning {

    /**
     * Signs a PDF with an RSA private key using SHA-256 digest.
     * This is the canonical iText signing pattern used by millions of
     * enterprise applications, government portals, and document workflows.
     *
     * The resulting signature is stored as a CMS (PKCS#7) SignedData
     * object inside the PDF, signed with RSA-2048 or RSA-4096.
     * The signature algorithm OID in the PDF will be:
     *   1.2.840.113549.1.1.11  (sha256WithRSAEncryption)
     *
     * No PQC OID (e.g. 2.16.840.1.101.3.4.3.17 for ML-DSA-65) is
     * recognized by Adobe Reader, LibreOffice, or any OS PDF viewer.
     */
    public void signPdf(String src, String dest,
                        PrivateKey privateKey, Certificate[] chain)
            throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader,
                new FileOutputStream(dest), new StampingProperties());

        /* IExternalSignature implementation that uses RSA.
         * PrivateKeySignature.getEncryptionAlgorithm() returns "RSA".
         * getHashAlgorithm() returns "SHA-256".
         * The resulting OID is sha256WithRSAEncryption.
         * On JDK < 24, passing an ML-DSA key here would throw
         * NoSuchAlgorithmException. */
        IExternalSignature pks = new PrivateKeySignature(
                privateKey,
                DigestAlgorithms.SHA256,   /* hash algorithm */
                "BC"                       /* BouncyCastle provider */
        );
        IExternalDigest digest = new BouncyCastleDigest();

        /* Embed the CMS signature in the PDF.
         * CryptoStandard.CMS = PKCS#7 SignedData.
         * Every byte of the document is hashed; the hash is signed with RSA.
         * The signature covers the entire document except the signature
         * container itself (byte-range signature). */
        signer.signDetached(digest, pks, chain,
                null, null, null,
                0, PdfSigner.CryptoStandard.CMS);
    }

    /**
     * Verify a PDF signature — will pass for any RSA sig forged by a CRQC.
     * PdfDocument.getCatalog().getPdfObject() → AcroForm → Fields →
     * Widget → /V (signature dict) → /Contents (DER CMS blob) →
     * RSA_verify() → true.
     */
    public boolean verifySignature(String pdfPath) throws Exception {
        PdfDocument pdfDoc = new PdfDocument(new PdfReader(pdfPath));
        SignatureUtil signUtil = new SignatureUtil(pdfDoc);
        List<String> names = signUtil.getSignatureNames();
        for (String name : names) {
            PdfPKCS7 pkcs7 = signUtil.readSignatureData(name);
            /* verify() calls RSA_verify() under the hood.
             * A CRQC-forged signature will return true here. */
            if (!pkcs7.verifySignatureIntegrityAndAuthenticity())
                return false;
        }
        return true;
    }
}
